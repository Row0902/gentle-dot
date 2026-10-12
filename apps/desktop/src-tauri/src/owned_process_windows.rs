//! Private Windows child ownership. Explicit encodings; no ambient environment copy.
//! Job membership controls lifecycle, not sandboxing or service/WMI-created children.
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;

// Temporarily unwired until P02 native ownership; allowance limited to these helpers.
#[allow(dead_code)]
pub(super) fn command_line(executable: &OsStr, arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let exe: Vec<u16> = executable.encode_wide().collect();
    // Lexical policy only: drive-rooted or UNC, no device namespaces. No existence check.
    let drive = exe.len() >= 3
        && matches!(exe[0], 65..=90 | 97..=122)
        && exe[1] == 58
        && matches!(exe[2], 47 | 92);
    let unc = exe.starts_with(&[92, 92])
        && exe[2..].split(|c| *c == 92).take(3).count() == 3
        && exe[2..].split(|c| *c == 92).take(3).all(|p| !p.is_empty())
        && !matches!(exe.get(2), Some(46 | 63));
    if !(drive || unc)
        || exe.iter().enumerate().any(|(i, &c)| {
            c < 32 || matches!(c, 34 | 60 | 62 | 124 | 63 | 42) || (c == 58 && i != 1)
        })
    {
        return Err(invalid("invalid executable path"));
    }
    // CRT argv0 has special parsing: quotes group whitespace, backslashes are literal.
    // A quote cannot occur in this validated path. Always use an explicit application
    // path separately when this is eventually passed to CreateProcessW.
    let mut output = vec![34];
    output.extend(exe);
    output.push(34);
    for argument in arguments {
        let units: Vec<u16> = argument.encode_wide().collect();
        if units.contains(&0) {
            return Err(invalid("NUL in argument"));
        }
        output.extend([32, 34]);
        let mut slashes = 0;
        for c in units {
            if c == 92 {
                slashes += 1;
                continue;
            }
            // Before a quote: 2n+1 backslashes. Else: n literal backslashes.
            output.extend(std::iter::repeat_n(
                92,
                if c == 34 { 2 * slashes + 1 } else { slashes },
            ));
            slashes = 0;
            output.push(c);
        }
        // Before the closing quote all trailing backslashes must be doubled.
        output.extend(std::iter::repeat_n(92, 2 * slashes));
        output.push(34);
    }
    output.push(0);
    // CreateProcessW's 32,767-character limit includes the terminal UTF-16 NUL.
    if output.len() > 32_767 {
        return Err(invalid("command line exceeds UTF-16 limit"));
    }
    Ok(output)
}

#[allow(dead_code)]
pub(super) fn environment(entries: &[(OsString, OsString)]) -> io::Result<Vec<u16>> {
    // Bounded explicit key policy: ASCII letters/digits/underscore/dot/hyphen.
    // Uppercase ASCII canonical keys match Windows ordinal ignore-case ordering
    // for this supported alphabet, not general Unicode case comparison.
    // Values retain arbitrary non-NUL Windows UTF-16 units.
    let mut sorted = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let key: Vec<u16> = key.encode_wide().collect();
        let value: Vec<u16> = value.encode_wide().collect();
        if key.is_empty()
            || !key
                .iter()
                .all(|c| matches!(*c, 65..=90 | 97..=122 | 48..=57 | 95 | 46 | 45))
        {
            return Err(invalid("unsupported environment key"));
        }
        if value.contains(&0) {
            return Err(invalid("NUL in environment value"));
        }
        let folded: Vec<u16> = key
            .iter()
            .map(|&c| if (97..=122).contains(&c) { c - 32 } else { c })
            .collect();
        sorted.push((folded, key, value));
    }
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid("duplicate environment key"));
    }
    let mut output = Vec::new();
    for (_, key, value) in sorted {
        output.extend(key);
        output.push(61);
        output.extend(value);
        output.push(0);
    }
    if output.is_empty() {
        output.push(0);
    }
    output.push(0);
    Ok(output)
}

fn invalid(message: &'static str) -> io::Error {
    // Static diagnostics never disclose supplied arguments or environment values.
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

use std::mem::size_of;
use std::ptr::null;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

// Constructed only from successful creation APIs inside this module, never borrowed
// or foreign handles. No Clone, raw-handle conversion, PID constructor, or attach API.
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: each non-null handle has exactly one owning wrapper.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// Private attempt storage only: no sibling module can obtain child endpoints.
// All four ends start non-inheritable; only spawn briefly enables child ends.
struct StdioPipes {
    child_stdin: Handle,
    child_stdout: Handle,
    parent: ParentStdio,
}

#[allow(dead_code)]
pub(super) struct ParentStdio {
    pub(super) stdin: std::fs::File,
    pub(super) stdout: std::fs::File,
}

impl StdioPipes {
    fn create() -> io::Result<Self> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Pipes::CreatePipe;
        fn pair(parent_reads: bool) -> io::Result<(Handle, std::fs::File)> {
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 0,
            };
            let mut read = std::ptr::null_mut();
            let mut write = std::ptr::null_mut();
            // SAFETY: valid output pointers and security attributes; wrap both
            // successful outputs before any subsequent fallible operation.
            if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let (child, parent) = if parent_reads {
                (Handle(write), Handle(read))
            } else {
                (Handle(read), Handle(write))
            };
            if unsafe { SetHandleInformation(parent.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let parent = std::mem::ManuallyDrop::new(parent);
            // SAFETY: transfer sole ownership of the live parent endpoint to File.
            Ok((child, unsafe { std::fs::File::from_raw_handle(parent.0) }))
        }
        let (child_stdin, stdin) = pair(false)?;
        let (child_stdout, stdout) = pair(true)?;
        Ok(Self {
            child_stdin,
            child_stdout,
            parent: ParentStdio { stdin, stdout },
        })
    }
}

// Defense-in-depth for cooperating launchers only. Every future Windows launcher
// must acquire this same lock through its process creation. Arbitrary unrelated
// launches that do not cooperate can still inherit temporarily enabled handles.
static WINDOWS_SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Narrow, unwind-safe exposure window.
#[cfg(test)]
thread_local! {
    // Thread-local so parallel tests cannot intercept another spawn attempt.
    static STDIO_RACE_PROBE: std::cell::RefCell<Option<Box<dyn FnMut(HANDLE, [HANDLE; 2])>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn stdio_race_probe(process: HANDLE, handles: Option<[HANDLE; 2]>) {
    if let Some(handles) = handles {
        STDIO_RACE_PROBE.with(|probe| {
            if let Some(probe) = probe.borrow_mut().as_mut() {
                probe(process, handles);
            }
        });
    }
}

struct InheritanceWindow<'a> {
    handles: &'a [HANDLE; 2],
    active: bool,
    // Drop releases serialization only after Drop has restored inheritance flags.
    _spawn_guard: std::sync::MutexGuard<'static, ()>,
}
impl<'a> InheritanceWindow<'a> {
    fn enable(handles: &'a [HANDLE; 2]) -> io::Result<Self> {
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        let window = Self {
            handles,
            active: true,
            // Unwinding clears flags before releasing the lock, so a poisoned
            // lock can safely be recovered for subsequent cooperating launches.
            _spawn_guard: WINDOWS_SPAWN_LOCK
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        };
        for &handle in handles {
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(window)
    }
    fn clear(mut self) -> io::Result<()> {
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        let mut error = None;
        for &handle in self.handles {
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0
                && error.is_none()
            {
                error = Some(io::Error::last_os_error());
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for InheritanceWindow<'_> {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        if self.active {
            for &handle in self.handles {
                unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
            }
        }
    }
}

// Pointer-aligned backing storage must outlive both attribute update and spawn.
// Delete only after successful initialization, including update/create failures.
struct HandleList {
    storage: Vec<usize>,
}
impl HandleList {
    fn new() -> io::Result<Self> {
        let mut bytes = 0;
        // The size probe intentionally fails with ERROR_INSUFFICIENT_BUFFER.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let pointer = storage.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(pointer, 1, 0, &mut bytes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage })
    }
    fn install(&mut self, handles: &[HANDLE; 2]) -> io::Result<()> {
        // SAFETY: initialized list, exactly two live inheritable handles. The
        // caller keeps this array alive through CreateProcessW (lpValue lifetime).
        if unsafe {
            UpdateProcThreadAttribute(
                self.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of::<[HANDLE; 2]>(),
                std::ptr::null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for HandleList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

// This guard stays armed through ResumeThread. All `?` paths (and unwinding)
// terminate the newly created process before releasing process/thread/job handles.
struct PendingProcess {
    process: Option<Handle>,
    thread: Handle,
    job: Option<Handle>,
}
impl Drop for PendingProcess {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            // SAFETY: CreateProcessW granted termination/synchronization rights.
            // Wait only after successful termination; never hang on an API failure.
            unsafe {
                if TerminateProcess(process.0, 1) != 0 {
                    WaitForSingleObject(process.0, INFINITE);
                }
            }
        }
    }
}

// Native ownership has no PID/handle constructor, attachment method, or Clone.
// Only spawn can mint an owner; raw handles remain private to this module.
#[allow(dead_code)] // Internal until authenticated transport is implemented.
pub(super) struct OwnedProcess {
    job: Handle,
    process: Handle,
    stopped: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Created,
    Configured,
    Assigned,
}

#[allow(dead_code)] // Not yet connected to the public daemon facade.
impl OwnedProcess {
    pub(super) fn spawn(
        executable: &OsStr,
        arguments: &[OsString],
        entries: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        Self::spawn_observed(executable, arguments, entries, |_, _, _| Ok(()))
    }

    pub(super) fn spawn_with_stdio(
        executable: &OsStr,
        arguments: &[OsString],
        entries: &[(OsString, OsString)],
    ) -> io::Result<(Self, ParentStdio)> {
        // No caller-visible pipe creation, callback, or child-handle return.
        let pipes = StdioPipes::create()?;
        let (process, parent) = Self::spawn_attempt(
            executable,
            arguments,
            entries,
            Some(pipes),
            |_, _, _| Ok(()),
        )?;
        Ok((process, parent.expect("supplied pipes")))
    }

    // Private fault-injection/observation seam. Production cannot supply handles.
    fn spawn_observed(
        executable: &OsStr,
        arguments: &[OsString],
        entries: &[(OsString, OsString)],
        observe: impl FnMut(Stage, HANDLE, HANDLE) -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::spawn_attempt(executable, arguments, entries, None, observe)
            .map(|(process, _)| process)
    }

    fn spawn_attempt(
        executable: &OsStr,
        arguments: &[OsString],
        entries: &[(OsString, OsString)],
        pipes: Option<StdioPipes>,
        mut observe: impl FnMut(Stage, HANDLE, HANDLE) -> io::Result<()>,
    ) -> io::Result<(Self, Option<ParentStdio>)> {
        // Batch scripts require shell-specific quoting and are deliberately refused.
        // Ordinary Win32 paths strip trailing dots/spaces from the final component.
        // Preserve raw UTF-16 (including unpaired surrogates) while checking that
        // resolved suffix; lexical drive-rooted/UNC validation remains unchanged.
        let mut resolved: Vec<u16> = executable.encode_wide().collect();
        while matches!(resolved.last(), Some(32 | 46)) {
            resolved.pop();
        }
        let component = resolved
            .rsplit(|&unit| unit == 92 || unit == 47)
            .next()
            .unwrap_or(&[]);
        let suffix = component
            .get(component.len().saturating_sub(4)..)
            .unwrap_or(&[]);
        let suffix: Vec<u16> = suffix
            .iter()
            .map(|&unit| {
                if (97..=122).contains(&unit) {
                    unit - 32
                } else {
                    unit
                }
            })
            .collect();
        if suffix == [46, 66, 65, 84] || suffix == [46, 67, 77, 68] {
            return Err(invalid("batch executable requires a separate shell policy"));
        }
        let mut command = command_line(executable, arguments)?;
        let block = environment(entries)?;
        let application: Vec<u16> = executable.encode_wide().chain(std::iter::once(0)).collect();
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let handles = pipes
            .as_ref()
            .map(|pipes| [pipes.child_stdin.0, pipes.child_stdout.0]);
        // Allocate/initialize storage while every endpoint is non-inheritable.
        let mut attributes = handles.as_ref().map(|_| HandleList::new()).transpose()?;
        let mut extended = STARTUPINFOEXW::default();
        let window = handles
            .as_ref()
            .map(InheritanceWindow::enable)
            .transpose()?;
        if let (Some(handles), Some(attributes)) = (&handles, &mut attributes) {
            attributes.install(handles)?;
            extended.StartupInfo = STARTUPINFOW {
                cb: size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: handles[0],
                hStdOutput: handles[1],
                // Deliberately unavailable in this primitive-only mode. A third
                // inherited log handle would violate the two-handle contract.
                hStdError: std::ptr::null_mut(),
                ..Default::default()
            };
            extended.lpAttributeList = attributes.pointer();
        }
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: buffers and attribute storage/value remain live through spawn.
        // HANDLE_LIST restricts TRUE inheritance to precisely the two endpoints;
        // the no-handoff path retains FALSE, original flags and STARTUPINFOW.
        #[cfg(test)]
        stdio_race_probe(std::ptr::null_mut(), handles);
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                i32::from(pipes.is_some()),
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | if pipes.is_some() {
                        EXTENDED_STARTUPINFO_PRESENT
                    } else {
                        0
                    },
                block.as_ptr().cast(),
                null(),
                if pipes.is_some() {
                    &extended.StartupInfo
                } else {
                    &startup
                },
                &mut information,
            )
        };
        if created == 0 {
            // Preserve CreateProcessW's error before clearing flags changes it.
            let error = io::Error::last_os_error();
            if let Some(window) = window {
                let _ = window.clear();
            }
            return Err(error);
        }
        // Arm termination before a fallible flag reset on the success path.
        let mut pending = PendingProcess {
            process: Some(Handle(information.hProcess)),
            thread: Handle(information.hThread),
            job: None,
        };
        #[cfg(test)]
        stdio_race_probe(information.hProcess, handles);
        if let Some(window) = window {
            window.clear()?;
        }
        // The child now owns inherited copies. Drop parent copies of both child
        // endpoints before any observer/job/resume failure; retain parent endpoints
        // locally so every failure also closes them.
        let parent = pipes.map(|pipes| pipes.parent);
        observe(Stage::Created, information.hProcess, information.hThread)?;
        // SAFETY: null attributes => non-inheritable; null name => fresh unnamed job.
        let raw_job = unsafe { CreateJobObjectW(null(), null()) };
        if raw_job.is_null() {
            return Err(io::Error::last_os_error());
        }
        pending.job = Some(Handle(raw_job));
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: exact binding struct and byte size for the selected information class.
        if unsafe {
            SetInformationJobObject(
                raw_job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        observe(Stage::Configured, information.hProcess, information.hThread)?;
        // No breakaway workaround: nested-job restrictions fail closed and clean up.
        if unsafe { AssignProcessToJobObject(raw_job, information.hProcess) } == 0 {
            return Err(io::Error::last_os_error());
        }
        observe(Stage::Assigned, information.hProcess, information.hThread)?;
        if unsafe { ResumeThread(pending.thread.0) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        // Disarm only after successful resume. Pending drops the primary thread.
        Ok((
            Self {
                job: pending.job.take().expect("created job"),
                process: pending.process.take().expect("created process"),
                stopped: false,
            },
            parent,
        ))
    }

    pub(super) fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        // Retain the job until drop (kill-on-close fallback). On failure retain
        // retryability, never report simulated success or terminate by PID.
        if unsafe { TerminateJobObject(self.job.0, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.stopped = true;
        Ok(())
    }

    pub(super) fn wait(&self, milliseconds: u32) -> io::Result<Option<u32>> {
        match unsafe { WaitForSingleObject(self.process.0, milliseconds) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(code))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    #[cfg(test)]
    fn active_processes(&self) -> io::Result<u32> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.job.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(accounting.ActiveProcesses)
    }
}

// Dropping the sole job handle triggers kill-on-close, including descendants even
// if the immediate child has already exited. Handle fields then close normally.
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject};

    // The test executable is the fixture: no scripts, temporary files, PID attachment,
    // inherited secrets, or dependency on cmd.exe's non-CRT argument parser.
    fn fixture(role: &str) -> (OsString, Vec<OsString>, Vec<(OsString, OsString)>) {
        (
            std::env::current_exe().unwrap().into_os_string(),
            vec![
                "--exact".into(),
                "owned_process_windows::native_tests::windows_owned_fixture".into(),
                "--nocapture".into(),
            ],
            vec![("OWNED_PROCESS_TEST_ROLE".into(), role.into())],
        )
    }

    #[test]
    fn windows_owned_fixture() {
        match std::env::var("OWNED_PROCESS_TEST_ROLE").as_deref() {
            Ok("exit") => std::process::exit(37),
            Ok("channel") => {
                use std::io::{Read, Write};
                let mut marker = [0; 6];
                if std::io::stdin().read_exact(&mut marker).is_err() {
                    std::process::exit(91);
                }
                assert_eq!(&marker, b"marker");
                std::io::stdout().write_all(&marker).unwrap();
                std::io::stdout().flush().unwrap();
                std::process::exit(37);
            }
            Ok("roundtrip") => {
                let expected = ["", "a b", "a\tb", "a\"b", "x\\", "x\\\\\"y", "雪"];
                let args: Vec<OsString> = std::env::args_os().collect();
                assert_eq!(
                    &args[args.len() - expected.len()..],
                    &expected.map(OsString::from)
                );
                assert_eq!(
                    std::env::var_os("ROUNDTRIP_VALUE"),
                    Some("雪=two words".into())
                );
                std::process::exit(37);
            }
            Ok("pipe-cleanup") => {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::Foundation::GetHandleInformation;
                use windows_sys::Win32::System::Threading::GetProcessHandleCount;
                let count = || {
                    let mut count = 0;
                    assert_ne!(
                        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
                        0
                    );
                    count
                };
                let (exe, args, env) = fixture("exit");
                for (attempt, failure) in [Stage::Created, Stage::Configured, Stage::Assigned]
                    .into_iter()
                    .cycle()
                    .take(9)
                    .enumerate()
                {
                    let baseline = count();
                    let pipes = StdioPipes::create().unwrap();
                    let child_ends = [pipes.child_stdin.0, pipes.child_stdout.0];
                    let mut handles = vec![
                        pipes.parent.stdin.as_raw_handle(),
                        pipes.parent.stdout.as_raw_handle(),
                    ];
                    let mut observer = None;
                    let result = OwnedProcess::spawn_attempt(
                        &exe,
                        &args,
                        &env,
                        Some(pipes),
                        |stage, process, thread| {
                            if stage == Stage::Created {
                                // Check before job/observer allocation can reuse
                                // the already closed child-end handle values.
                                for handle in child_ends {
                                    let mut flags = 0;
                                    assert_eq!(
                                        unsafe { GetHandleInformation(handle, &mut flags) },
                                        0
                                    );
                                }
                            }
                            if stage == failure {
                                handles.extend([process, thread]);
                                observer = Some(duplicate(process));
                                return Err(io::Error::other("injected pipe failure"));
                            }
                            Ok(())
                        },
                    );
                    assert!(result.is_err());
                    let observer = observer.unwrap();
                    assert_eq!(
                        unsafe { WaitForSingleObject(observer.0, 10_000) },
                        WAIT_OBJECT_0
                    );
                    let mut code = 0;
                    assert_ne!(unsafe { GetExitCodeProcess(observer.0, &mut code) }, 0);
                    assert_eq!(code, 1);
                    for handle in handles {
                        let mut flags = 0;
                        assert_eq!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
                    }
                    drop(observer);
                    if attempt >= 3 {
                        assert_eq!(count(), baseline, "pipe/process/thread/job handle leak");
                    }
                }
                std::process::exit(37);
            }
            Ok("handles") => {
                // Dedicated fixture process avoids parallel test handle churn. This
                // proves no net OS handle growth for these repeated paths, not that
                // arbitrary external API failures can never prevent OS cleanup.
                use windows_sys::Win32::System::Threading::GetProcessHandleCount;
                let count = || {
                    let mut count = 0;
                    assert_ne!(
                        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
                        0
                    );
                    count
                };
                let (exe, args, env) = fixture("exit");
                let failures = || {
                    for failure in [Stage::Created, Stage::Configured, Stage::Assigned] {
                        assert!(
                            OwnedProcess::spawn_observed(&exe, &args, &env, |stage, _, _| {
                                if stage == failure {
                                    Err(io::Error::other("injected failure"))
                                } else {
                                    Ok(())
                                }
                            })
                            .is_err()
                        );
                    }
                };
                failures(); // Warm up any lazily initialized OS/runtime state.
                let baseline = count();
                for _ in 0..16 {
                    failures();
                }
                assert_eq!(count(), baseline, "pre-resume failures leaked OS handles");
                for _ in 0..16 {
                    let mut child = OwnedProcess::spawn(&exe, &args, &env).unwrap();
                    assert_eq!(child.wait(10_000).unwrap(), Some(37));
                    child.stop().unwrap();
                    child.stop().unwrap();
                }
                assert_eq!(count(), baseline, "successful owners leaked OS handles");
                std::process::exit(37);
            }
            Ok(role @ ("parent" | "parent-exit")) => {
                let (exe, args, _) = fixture("descendant");
                let _child = std::process::Command::new(exe)
                    .args(args)
                    .env_clear()
                    .env("OWNED_PROCESS_TEST_ROLE", "descendant")
                    .spawn()
                    .unwrap();
                if role == "parent-exit" {
                    std::process::exit(37);
                }
                std::thread::sleep(Duration::from_secs(60));
            }
            Ok("descendant") => std::thread::sleep(Duration::from_secs(60)),
            _ => (),
        }
    }

    #[test]
    fn windows_owned_stdio_spawn_only_surface() {
        // Structural guard, not a runtime inheritance proof: sibling modules must
        // not obtain the private child-end bundle or pass one into public spawn.
        let source = include_str!("owned_process_windows.rs");
        assert!(!source.contains(concat!("pub(super) struct ", "StdioPipes")));
        let signature = source
            .split("pub(super) fn spawn_with_stdio(")
            .nth(1)
            .unwrap()
            .split("->")
            .next()
            .unwrap();
        assert!(!signature.contains("StdioPipes"));
    }

    #[test]
    fn windows_owned_stdio_initially_noninheritable() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
        let pipes = StdioPipes::create().unwrap();
        let handles = [pipes.child_stdin.0, pipes.child_stdout.0];
        let flags = |handle| {
            let mut flags = 0;
            assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
            flags & HANDLE_FLAG_INHERIT
        };
        for handle in [
            handles[0],
            handles[1],
            pipes.parent.stdin.as_raw_handle(),
            pipes.parent.stdout.as_raw_handle(),
        ] {
            assert_eq!(flags(handle), 0);
        }
        // Both normal reset and early-return/unwind fallback restore the flags.
        for explicit_reset in [false, true] {
            let window = InheritanceWindow::enable(&handles).unwrap();
            for handle in handles {
                assert_ne!(flags(handle), 0);
            }
            assert_eq!(flags(pipes.parent.stdin.as_raw_handle()), 0);
            assert_eq!(flags(pipes.parent.stdout.as_raw_handle()), 0);
            if explicit_reset {
                window.clear().unwrap();
            } else {
                drop(window);
            }
            for handle in handles {
                assert_eq!(flags(handle), 0);
            }
        }
        let partial = [handles[0], std::ptr::null_mut()];
        assert!(InheritanceWindow::enable(&partial).is_err());
        assert_eq!(flags(handles[0]), 0);
    }

    #[test]
    #[ignore = "known non-cooperating inheritance gap; prerequisite before real Windows daemon orchestration wiring (currently Unsupported)"]
    fn windows_owned_stdio_unrelated_concurrent_launch() {
        use std::io::{Read, Write};
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::Foundation::{
            CompareObjectHandles, GetHandleInformation, HANDLE_FLAG_INHERIT,
        };
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Threading::CreateEventW;

        fn has_object(process: HANDLE, handle: HANDLE) -> bool {
            let mut copied = std::ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    process,
                    handle,
                    GetCurrentProcess(),
                    &mut copied,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(6));
                return false;
            }
            let copied = Handle(copied);
            unsafe { CompareObjectHandles(copied.0, handle) != 0 }
        }
        struct ResetProbe;
        impl Drop for ResetProbe {
            fn drop(&mut self) {
                STDIO_RACE_PROBE.with(|probe| *probe.borrow_mut() = None);
            }
        }
        let _reset = ResetProbe;
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let excluded = Handle(unsafe { CreateEventW(&security, 1, 0, null()) });
        assert!(!excluded.0.is_null());
        let excluded_value = excluded.0 as usize;
        STDIO_RACE_PROBE.with(|probe| {
            *probe.borrow_mut() = Some(Box::new(move |process, handles| {
                let excluded = excluded_value as HANDLE;
                if !process.is_null() {
                    // The intended child is still suspended and parent child-end
                    // copies are live: compare identity, not just numeric presence.
                    for handle in handles {
                        assert!(has_object(process, handle));
                    }
                    assert!(!has_object(process, excluded));
                    return;
                }
                for handle in handles {
                    let mut flags = 0;
                    assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
                    assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
                }
                // The owning thread stays inside the enabled window until the
                // separate ordinary Command launcher completes its real OS spawn.
                // Suspended helpers prevent runtime handle reuse and need no IPC.
                let (send, receive) = std::sync::mpsc::sync_channel(1);
                let launcher = std::thread::spawn(move || {
                    let (exe, args, _) = fixture("exit");
                    let child = std::process::Command::new(exe)
                        .args(args)
                        .env_clear()
                        .env("OWNED_PROCESS_TEST_ROLE", "exit")
                        .creation_flags(CREATE_SUSPENDED)
                        .spawn()
                        .unwrap();
                    if let Err(error) = send.send(child) {
                        let mut child = error.0;
                        child.kill().unwrap();
                        child.wait().unwrap();
                    }
                });
                let mut helper = receive.recv_timeout(Duration::from_secs(10)).unwrap();
                launcher.join().unwrap();
                let leaked = handles.map(|handle| has_object(helper.as_raw_handle(), handle));
                helper.kill().unwrap();
                helper.wait().unwrap();

                // Positive control: unrestricted native TRUE inheritance must
                // deliver both exact objects, validating the same identity probe.
                let (exe, args, env) = fixture("exit");
                let application: Vec<u16> = exe.encode_wide().chain(Some(0)).collect();
                let mut command = command_line(&exe, &args).unwrap();
                let block = environment(&env).unwrap();
                let startup = STARTUPINFOW {
                    cb: size_of::<STARTUPINFOW>() as u32,
                    ..Default::default()
                };
                let mut information = PROCESS_INFORMATION::default();
                assert_ne!(
                    unsafe {
                        CreateProcessW(
                            application.as_ptr(),
                            command.as_mut_ptr(),
                            null(),
                            null(),
                            1,
                            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                            block.as_ptr().cast(),
                            null(),
                            &startup,
                            &mut information,
                        )
                    },
                    0
                );
                let _control = PendingProcess {
                    process: Some(Handle(information.hProcess)),
                    thread: Handle(information.hThread),
                    job: None,
                };
                for handle in handles {
                    assert!(
                        has_object(information.hProcess, handle),
                        "positive control missed pipe"
                    );
                }
                assert_eq!(
                    leaked,
                    [false, false],
                    "unrelated Command inherited child pipes"
                );
            }));
        });
        let (exe, args, env) = fixture("channel");
        let (child, mut parent) = OwnedProcess::spawn_with_stdio(&exe, &args, &env).unwrap();
        parent.stdin.write_all(b"marker").unwrap();
        drop(parent.stdin);
        assert_eq!(child.wait(10_000).unwrap(), Some(37));
        let mut output = Vec::new();
        parent.stdout.take(4096).read_to_end(&mut output).unwrap();
        assert!(output.ends_with(b"marker"), "{output:?}");
        // A pass confirms only this ordinary Command scenario in this tested live
        // window, not universal safety against arbitrary unrestricted launchers.
    }

    #[test]
    fn windows_owned_stdio_cooperative_launch() {
        use std::io::{Read, Write};
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::Foundation::CompareObjectHandles;
        let (attempted_send, attempted_receive) = std::sync::mpsc::sync_channel(1);
        let (finished_send, finished_receive) = std::sync::mpsc::sync_channel(1);
        struct ResetProbe;
        impl Drop for ResetProbe {
            fn drop(&mut self) {
                STDIO_RACE_PROBE.with(|probe| *probe.borrow_mut() = None);
            }
        }
        let _reset = ResetProbe;
        let mut sender = Some((attempted_send, finished_send));
        STDIO_RACE_PROBE.with(|probe| {
            *probe.borrow_mut() = Some(Box::new(move |process, handles| {
                if !process.is_null() {
                    return;
                }
                let (attempted, finished) = sender.take().unwrap();
                // Retain non-inheritable identity references after spawn closes
                // its original child ends. Transfer sole ownership to the worker.
                let references = handles.map(|handle| {
                    let reference = std::mem::ManuallyDrop::new(duplicate(handle));
                    (handle as usize, reference.0 as usize)
                });
                std::thread::spawn(move || {
                    let references = references
                        .map(|(value, reference)| (value as HANDLE, Handle(reference as HANDLE)));
                    let blocked = matches!(
                        WINDOWS_SPAWN_LOCK.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    );
                    attempted.send(blocked).unwrap();
                    if !blocked {
                        return;
                    }
                    let _guard = WINDOWS_SPAWN_LOCK
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let (exe, args, _) = fixture("exit");
                    let mut helper = std::process::Command::new(exe)
                        .args(args)
                        .env_clear()
                        .env("OWNED_PROCESS_TEST_ROLE", "exit")
                        .creation_flags(CREATE_SUSPENDED)
                        .spawn()
                        .unwrap();
                    let leaked = references.map(|(value, reference)| {
                        let mut copied = std::ptr::null_mut();
                        if unsafe {
                            DuplicateHandle(
                                helper.as_raw_handle(),
                                value,
                                GetCurrentProcess(),
                                &mut copied,
                                0,
                                0,
                                DUPLICATE_SAME_ACCESS,
                            )
                        } == 0
                        {
                            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(6));
                            return false;
                        }
                        let copied = Handle(copied);
                        unsafe { CompareObjectHandles(copied.0, reference.0) != 0 }
                    });
                    helper.kill().unwrap();
                    let waited = unsafe { WaitForSingleObject(helper.as_raw_handle(), 10_000) };
                    assert_eq!(waited, WAIT_OBJECT_0);
                    helper.wait().unwrap();
                    finished.send((leaked, waited)).unwrap();
                });
                assert!(
                    attempted_receive
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap(),
                    "cooperating launcher acquired lock inside inheritance window"
                );
                // No sleeps: try_lock proved exclusion on the worker thread;
                // returning lets the owned launch clear flags and release the lock.
            }));
        });
        let (exe, args, env) = fixture("channel");
        let (child, mut parent) = OwnedProcess::spawn_with_stdio(&exe, &args, &env).unwrap();
        let (leaked, waited) = finished_receive
            .recv_timeout(Duration::from_secs(20))
            .unwrap();
        assert_eq!(leaked, [false, false]);
        assert_eq!(waited, WAIT_OBJECT_0);
        parent.stdin.write_all(b"marker").unwrap();
        drop(parent.stdin);
        assert_eq!(child.wait(10_000).unwrap(), Some(37));
        let mut output = Vec::new();
        parent.stdout.take(4096).read_to_end(&mut output).unwrap();
        assert!(output.ends_with(b"marker"), "{output:?}");
        // This proves cooperating serialization, not safety for arbitrary launchers.
    }

    #[test]
    fn windows_owned_stdio_roundtrip() {
        use std::io::{Read, Write};
        let (exe, args, env) = fixture("channel");
        let (child, mut parent) = OwnedProcess::spawn_with_stdio(&exe, &args, &env).unwrap();
        parent.stdin.write_all(b"marker").unwrap();
        drop(parent.stdin);
        assert_eq!(child.wait(10_000).unwrap(), Some(37));
        let mut output = Vec::new();
        parent.stdout.take(4096).read_to_end(&mut output).unwrap();
        assert!(output.ends_with(b"marker"), "{output:?}");
    }

    #[test]
    fn windows_owned_stdio_handle_restriction() {
        use std::io::Write;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Threading::CreateEventW;
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let event = Handle(unsafe { CreateEventW(&security, 1, 0, null()) });
        let job = Handle(unsafe { CreateJobObjectW(&security, null()) });
        assert!(!event.0.is_null() && !job.0.is_null());
        let mut pipes = StdioPipes::create().unwrap();
        for handle in [
            pipes.parent.stdin.as_raw_handle(),
            pipes.parent.stdout.as_raw_handle(),
        ] {
            let mut flags = 0;
            assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        }
        for handle in [pipes.child_stdin.0, pipes.child_stdout.0] {
            let mut flags = 0;
            assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        }
        for handle in [event.0, job.0] {
            let mut flags = 0;
            assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
            assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
        }
        // Inspect the suspended child's actual handles before its runtime can
        // reuse absent numeric values. Compare kernel-object identity rather than
        // treating any unrelated handle at the same numeric value as inheritance.
        fn has_object(process: HANDLE, handle: HANDLE) -> bool {
            use windows_sys::Win32::Foundation::CompareObjectHandles;
            let mut copied = std::ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    process,
                    handle,
                    GetCurrentProcess(),
                    &mut copied,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(6));
                return false;
            }
            let copied = Handle(copied);
            unsafe { CompareObjectHandles(copied.0, handle) != 0 }
        }
        let excluded = [
            event.0,
            job.0,
            pipes.parent.stdin.as_raw_handle(),
            pipes.parent.stdout.as_raw_handle(),
        ];
        let included = [pipes.child_stdin.0, pipes.child_stdout.0];
        let (exe, args, env) = fixture("channel");
        pipes.parent.stdin.write_all(b"marker").unwrap();
        let (child, parent) = OwnedProcess::spawn_attempt(
            &exe,
            &args,
            &env,
            Some(pipes),
            |stage, process, thread| {
                if stage == Stage::Created {
                    for handle in excluded {
                        assert!(!has_object(process, handle), "unlisted object inherited");
                    }
                    // Child ends have already closed in the parent, so their numeric
                    // values can only be checked for presence in the suspended child.
                    for handle in included {
                        let mut copied = std::ptr::null_mut();
                        assert_ne!(
                            unsafe {
                                DuplicateHandle(
                                    process,
                                    handle,
                                    GetCurrentProcess(),
                                    &mut copied,
                                    0,
                                    0,
                                    DUPLICATE_SAME_ACCESS,
                                )
                            },
                            0
                        );
                        drop(Handle(copied));
                    }
                    for handle in [process, thread] {
                        let mut flags = 0;
                        assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
                        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
                    }
                }
                Ok(())
            },
        )
        .unwrap();
        let parent = parent.unwrap();
        assert_eq!(child.wait(10_000).unwrap(), Some(37));
        let mut flags = 0;
        assert_ne!(unsafe { GetHandleInformation(child.job.0, &mut flags) }, 0);
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        // Positive control: ordinary TRUE inheritance really delivers the separately
        // inheritable event/job, proving the child's absence probe is meaningful.
        let (exe, args, env) = fixture("exit");
        let application: Vec<u16> = exe.encode_wide().chain(std::iter::once(0)).collect();
        let mut command = command_line(&exe, &args).unwrap();
        let block = environment(&env).unwrap();
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        assert_ne!(
            unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    block.as_ptr().cast(),
                    null(),
                    &startup,
                    &mut information,
                )
            },
            0
        );
        let control = PendingProcess {
            process: Some(Handle(information.hProcess)),
            thread: Handle(information.hThread),
            job: None,
        };
        assert!(has_object(information.hProcess, event.0));
        assert!(has_object(information.hProcess, job.0));
        assert!(!has_object(
            information.hProcess,
            parent.stdout.as_raw_handle()
        ));
        assert!(!has_object(
            information.hProcess,
            parent.stdin.as_raw_handle()
        ));
        assert_ne!(unsafe { ResumeThread(information.hThread) }, u32::MAX);
        assert_eq!(
            unsafe { WaitForSingleObject(information.hProcess, 10_000) },
            WAIT_OBJECT_0
        );
        let mut code = 0;
        assert_ne!(
            unsafe { GetExitCodeProcess(information.hProcess, &mut code) },
            0
        );
        assert_eq!(code, 37);
        drop(control);
    }

    #[test]
    fn windows_owned_stdio_failure_cleanup() {
        let (exe, args, env) = fixture("pipe-cleanup");
        let child = OwnedProcess::spawn(&exe, &args, &env).unwrap();
        assert_eq!(child.wait(30_000).unwrap(), Some(37));
    }

    #[test]
    fn windows_owned_suspended_assign_resume_exit() {
        let (exe, args, env) = fixture("exit");
        let mut stages = 0;
        let mut child = OwnedProcess::spawn_observed(&exe, &args, &env, |_, process, _| {
            // The exit fixture cannot run at ANY pre-resume checkpoint.
            assert_eq!(unsafe { WaitForSingleObject(process, 50) }, WAIT_TIMEOUT);
            stages += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(stages, 3);
        assert_eq!(child.wait(10_000).unwrap(), Some(37));
        child.stop().unwrap();
        child.stop().unwrap();
    }

    #[test]
    fn windows_owned_os_roundtrip_and_handle_counts() {
        for role in ["roundtrip", "handles"] {
            let (exe, mut args, mut env) = fixture(role);
            if role == "roundtrip" {
                args.push("--".into());
                args.extend(
                    ["", "a b", "a\tb", "a\"b", "x\\", "x\\\\\"y", "雪"].map(OsString::from),
                );
                env.push(("ROUNDTRIP_VALUE".into(), "雪=two words".into()));
            }
            let child = OwnedProcess::spawn(&exe, &args, &env).unwrap();
            assert_eq!(child.wait(30_000).unwrap(), Some(37));
        }
        for path in ["C:\\test.cmd", "C:\\test.BAT"] {
            assert_eq!(
                OwnedProcess::spawn(OsStr::new(path), &[], &[])
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn windows_owned_stop_after_parent_exit_keeps_descendant_owned() {
        let (exe, args, env) = fixture("parent-exit");
        let mut child = OwnedProcess::spawn(&exe, &args, &env).unwrap();
        assert_eq!(child.wait(10_000).unwrap(), Some(37));
        await_count(&child, 1);
        child.stop().unwrap();
        await_count(&child, 0);
        child.stop().unwrap();
    }

    fn await_count(child: &OwnedProcess, expected: u32) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.active_processes().unwrap() == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "job never reached {expected} live processes"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn windows_owned_stop_descendants_idempotent() {
        let (exe, args, env) = fixture("parent");
        let mut child = OwnedProcess::spawn(&exe, &args, &env).unwrap();
        await_count(&child, 2);
        assert_eq!(child.wait(0).unwrap(), None);
        child.stop().unwrap();
        await_count(&child, 0);
        assert!(child.wait(10_000).unwrap().is_some());
        child.stop().unwrap();
    }

    struct Observer(HANDLE);
    impl Drop for Observer {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn duplicate(process: HANDLE) -> Observer {
        let mut handle = std::ptr::null_mut();
        let current = unsafe { GetCurrentProcess() };
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    current,
                    process,
                    current,
                    &mut handle,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        Observer(handle)
    }

    #[test]
    fn windows_owned_pre_resume_failure_cleanup() {
        let (exe, args, env) = fixture("exit");
        for failure in [Stage::Created, Stage::Configured, Stage::Assigned] {
            let mut observer = None;
            let result = OwnedProcess::spawn_observed(&exe, &args, &env, |stage, process, _| {
                if stage == failure {
                    observer = Some(duplicate(process));
                    return Err(io::Error::other("injected pre-resume failure"));
                }
                Ok(())
            });
            assert!(result.is_err());
            let observer = observer.expect("must reach real process creation");
            assert_eq!(
                unsafe { WaitForSingleObject(observer.0, 10_000) },
                WAIT_OBJECT_0
            );
        }
        assert!(OwnedProcess::spawn(
            OsStr::new("C:\\nonexistent-owned-process-test\\missing.exe"),
            &[],
            &[]
        )
        .is_err());
    }

    #[test]
    fn windows_owned_batch_dotfile_bat_refused() {
        assert_eq!(
            OwnedProcess::spawn(OsStr::new("C:\\.bat"), &[], &[])
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn windows_owned_batch_dotfile_cmd_refused() {
        assert_eq!(
            OwnedProcess::spawn(OsStr::new("C:\\.cmd"), &[], &[])
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn windows_owned_batch_dotfile_normalized_refused() {
        for path in ["C:\\.bat. ", "C:\\dir\\.BaT", "C:\\.CMD. "] {
            assert_eq!(
                OwnedProcess::spawn(OsStr::new(path), &[], &[])
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "batch path accepted: {path}"
            );
        }
    }

    #[test]
    fn windows_owned_batch_suffix_txt_allowed() {
        // A missing executable reaches Win32: it is not rejected by batch policy.
        assert_eq!(
            OwnedProcess::spawn(OsStr::new("C:\\x.bat.txt"), &[], &[])
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn windows_owned_batch_directory_allowed() {
        assert_eq!(
            OwnedProcess::spawn(OsStr::new("C:\\dir.bat\\x.exe"), &[], &[])
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn windows_owned_batch_trailing_dot_space_refused() {
        for path in ["C:\\x.bat.", "C:\\x.bat ", "C:\\x.CMD. "] {
            assert_eq!(
                OwnedProcess::spawn(OsStr::new(path), &[], &[])
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "batch path accepted: {path}"
            );
        }
    }

    #[test]
    fn windows_owned_drop_kills_job() {
        let (exe, args, env) = fixture("parent-exit");
        let mut child = OwnedProcess::spawn(&exe, &args, &env).unwrap();
        assert_eq!(child.wait(10_000).unwrap(), Some(37));
        await_count(&child, 1);
        // Test-only inspection of this fresh owned job, never arbitrary PID attachment.
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicProcessIdList, QueryInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
        #[repr(C)]
        struct ProcessIds {
            assigned: u32,
            listed: u32,
            ids: [usize; 2],
        }
        let mut ids = ProcessIds {
            assigned: 0,
            listed: 0,
            ids: [0; 2],
        };
        assert_ne!(
            unsafe {
                QueryInformationJobObject(
                    child.job.0,
                    JobObjectBasicProcessIdList,
                    (&mut ids as *mut ProcessIds).cast(),
                    size_of::<ProcessIds>() as u32,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(ids.listed, 1);
        let grandchild = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, ids.ids[0] as u32) };
        assert!(!grandchild.is_null());
        let grandchild = Observer(grandchild);
        let observer = Some(duplicate(grandchild.0));
        assert_eq!(
            unsafe { WaitForSingleObject(observer.as_ref().unwrap().0, 0) },
            WAIT_TIMEOUT,
            "observer must independently track the still-live grandchild"
        );
        // Test only: suppress the explicit termination path so the real last-handle
        // close must kill the child. Production never marks stopped before success.
        child.stopped = true;
        drop(child);
        assert_eq!(
            unsafe { WaitForSingleObject(observer.unwrap().0, 10_000) },
            WAIT_OBJECT_0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn windows_encoding_arguments() {
        let args = ["", "a b", "a\tb", "a\"b", "x\\", "x\\\\\"y", "雪"].map(OsString::from);
        let mut expected = wide("\"C:\\Program Files\\tool.exe\" \"\" \"a b\" \"a\tb\" \"a\\\"b\" \"x\\\\\" \"x\\\\\\\\\\\"y\" \"雪\"");
        expected.push(0);
        assert_eq!(
            command_line(OsStr::new("C:\\Program Files\\tool.exe"), &args).unwrap(),
            expected
        );
    }

    #[test]
    fn windows_encoding_executable_token() {
        let mut expected = wide("\"C:\\tool\\\"");
        expected.push(0);
        // argv0 quotes delimit the token; trailing backslashes are NOT doubled.
        assert_eq!(
            command_line(OsStr::new("C:\\tool\\"), &[]).unwrap(),
            expected
        );
        for bad in [
            "",
            "tool.exe",
            "C:tool.exe",
            "\\tool.exe",
            "C:\\a\"b",
            "C:\\a\0b",
            "C:\\a|b",
        ] {
            assert!(command_line(OsStr::new(bad), &[]).is_err());
        }
        assert!(command_line(OsStr::new("\\\\server\\share\\tool.exe"), &[]).is_ok());
    }

    #[test]
    fn windows_encoding_raw_utf16_and_nul() {
        let raw = OsString::from_wide(&[0xd800, 0x96ea]);
        let mut expected = wide("\"C:\\tool.exe\" \"");
        expected.extend([0xd800, 0x96ea, 34, 0]);
        assert_eq!(
            command_line(OsStr::new("C:\\tool.exe"), &[raw.clone()]).unwrap(),
            expected
        );
        let exe = OsString::from_wide(&[67, 58, 92, 0xd800]);
        assert_eq!(
            command_line(&exe, &[]).unwrap(),
            vec![34, 67, 58, 92, 0xd800, 34, 0]
        );
        assert!(command_line(OsStr::new("C:\\tool.exe"), &[OsString::from("a\0b")]).is_err());
        assert_eq!(
            environment(&[("KEY".into(), raw)]).unwrap(),
            vec![75, 69, 89, 61, 0xd800, 0x96ea, 0, 0]
        );
    }

    #[test]
    fn windows_encoding_size_limit() {
        // Quoted C:\\x is six units, separator plus quotes three, final NUL one.
        let accepted = OsString::from("a".repeat(32_757));
        assert_eq!(
            command_line(OsStr::new("C:\\x"), &[accepted])
                .unwrap()
                .len(),
            32_767
        );
        assert!(command_line(OsStr::new("C:\\x"), &[OsString::from("a".repeat(32_758))]).is_err());
    }

    #[test]
    fn windows_encoding_environment_ordinal_order() {
        // Windows ordinal ignore-case uses uppercase ordering, not lowercase ordering.
        let entries = [
            "_X", "a_B", "Alpha", "aB", "z", "a", "_", "-x", "_x2", ".x", "1x",
        ]
        .map(|key| (OsString::from(key), OsString::from("")));
        assert_eq!(
            environment(&entries).unwrap(),
            wide("-x=\0.x=\01x=\0a=\0aB=\0Alpha=\0a_B=\0z=\0_=\0_X=\0_x2=\0\0")
        );
        // Original spelling survives sorting; equality still ignores ASCII case.
        assert!(environment(&[("Path".into(), "".into()), ("PATH".into(), "".into())]).is_err());
    }

    #[test]
    fn windows_encoding_environment() {
        assert_eq!(environment(&[]).unwrap(), vec![0, 0]);
        let entries = [
            ("z".into(), "雪=ok".into()),
            ("Alpha".into(), "".into()),
            ("b".into(), "two".into()),
        ];
        assert_eq!(
            environment(&entries).unwrap(),
            wide("Alpha=\0b=two\0z=雪=ok\0\0")
        );
        assert!(environment(&[("Path".into(), "a".into()), ("PATH".into(), "b".into())]).is_err());
        for key in ["", "A=B", "A\0B", "é", "A B", "A\tB"] {
            assert!(environment(&[(key.into(), "value".into())]).is_err());
        }
        assert!(environment(&[("KEY".into(), "a\0b".into())]).is_err());
        assert!(environment(&[
            ("SystemRoot".into(), "C:\\Windows".into()),
            ("_X.1-".into(), "ok".into())
        ])
        .is_ok());
    }
}
