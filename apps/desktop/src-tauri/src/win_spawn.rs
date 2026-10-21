//! Spawns the daemon on Windows with exactly the handles it needs (W29): stdin from `NUL` and its
//! output in the log, nothing else.
//!
//! `std::process::Command` lets the child inherit every inheritable handle of the app. Here the
//! child is created with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, so only the listed handles reach it,
//! whatever else in the app is inheritable. The daemon's channel is a named pipe it opens by name
//! (`GENTLE_DOT_CHANNEL_PIPE`), so no channel handle is passed and `STARTUPINFO.lpReserved2` (the C
//! runtime's descriptor table) is left unset.
//!
//! The listed handles are inheritable copies made just before `CreateProcessW` and closed right
//! after it. While they exist, a process another thread of the app spawns with plain inheritance
//! could get them too; the window is that one call.
//!
//! The creation flags are the ones `std::process::Command` passes for such a spawn
//! (`CREATE_UNICODE_ENVIRONMENT`, plus `EXTENDED_STARTUPINFO_PRESENT` for the attribute list), so
//! the daemon's console and process group are what they were. The Job the daemon joins is the
//! caller's (`daemon::create_daemon_job`, `daemon::assign_to_job`).

use crate::daemon::ChildProcess;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::marker::PhantomData;
use std::process::ExitStatus;
use std::{mem, ptr};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, HANDLE, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess, InitializeProcThreadAttributeList,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

/// What to start: a program, its arguments, and the variables set over the app's environment.
pub struct Spawn<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    pub envs: &'a [(String, String)],
}

/// A process this app started, owned through its process handle.
#[derive(Debug)]
pub struct WinChild {
    process: OwnedHandle,
    pid: u32,
    status: Option<ExitStatus>,
}

/// Starts `spawn` with stdin `NUL`, stdout and stderr `log`, and no other handle of the app.
pub fn spawn(spawn: &Spawn<'_>, log: &File) -> io::Result<WinChild> {
    let program = resolve(spawn.program, path_of(spawn.envs).as_deref())?;
    let mut command_line = wide_nul(command_line(spawn.program, spawn.args));
    let environment = environment_block(spawn.envs);
    let application = wide_nul(program.as_os_str());

    // Read-only, as `std::process::Stdio::null` opens it for stdin.
    let nul = File::open("NUL")?;
    let nul = inheritable(borrow(&nul))?;
    let out = inheritable(borrow(log))?;

    let mut listed: Vec<HANDLE> = vec![raw(&nul), raw(&out)];
    let mut attributes = AttributeList::with_handles(&mut listed)?;

    // SAFETY: an all-zero STARTUPINFOEXW is valid.
    let mut startup: STARTUPINFOEXW = unsafe { mem::zeroed() };
    startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = raw(&nul);
    startup.StartupInfo.hStdOutput = raw(&out);
    startup.StartupInfo.hStdError = raw(&out);
    startup.lpAttributeList = attributes.as_ptr();

    // SAFETY: an all-zero PROCESS_INFORMATION is valid.
    let mut info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: every pointer is valid for the call: NUL-terminated application name, a mutable
    // command line, a double-NUL environment block, a startup info whose attribute list outlives
    // the call.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            TRUE,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            ptr::null(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    let error = io::Error::last_os_error();
    drop(attributes);
    // The inheritable copies close here; the child holds its own.
    drop((nul, out));
    if created == 0 {
        return Err(error);
    }
    // SAFETY: the handles CreateProcessW returned, now owned.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) };
    // SAFETY: as above; the thread handle is not needed and closes here.
    drop(unsafe { OwnedHandle::from_raw_handle(info.hThread as RawHandle) });
    Ok(WinChild { process, pid: info.dwProcessId, status: None })
}

fn borrow(file: &File) -> BorrowedHandle<'_> {
    use std::os::windows::io::AsHandle;
    file.as_handle()
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

/// An inheritable copy of `handle`, for the child only (it is listed in the handle list).
fn inheritable(handle: BorrowedHandle<'_>) -> io::Result<OwnedHandle> {
    let mut copy: HANDLE = ptr::null_mut();
    // SAFETY: duplicating a handle we hold within this process.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle.as_raw_handle() as HANDLE,
            GetCurrentProcess(),
            &mut copy,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: DuplicateHandle returned a handle we now own.
    Ok(unsafe { OwnedHandle::from_raw_handle(copy as RawHandle) })
}

/// A `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` over `handles`. The list points into the slice, so it
/// borrows it: the slice cannot go away while the list exists.
struct AttributeList<'a> {
    buffer: Vec<usize>,
    _handles: PhantomData<&'a mut [HANDLE]>,
}

impl<'a> AttributeList<'a> {
    fn with_handles(handles: &'a mut [HANDLE]) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: a size query for one attribute.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        let mut list =
            AttributeList { buffer: vec![0usize; size.div_ceil(mem::size_of::<usize>())], _handles: PhantomData };
        // SAFETY: the buffer holds `size` bytes, aligned for the list.
        if unsafe { InitializeProcThreadAttributeList(list.as_ptr(), 1, 0, &mut size) } == 0 {
            list.buffer.clear();
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the list was initialized above; `handles` outlives the list (it borrows it for 'a).
        let updated = unsafe {
            UpdateProcThreadAttribute(
                list.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast(),
                mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if updated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(list)
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList<'_> {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            // SAFETY: the list was initialized in `with_handles`.
            unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
        }
    }
}

/// `program` and `args` quoted the way the C runtime splits a command line.
pub fn command_line(program: &str, args: &[String]) -> String {
    let mut line = String::new();
    quote(program, &mut line);
    for arg in args {
        line.push(' ');
        quote(arg, &mut line);
    }
    line
}

fn quote(arg: &str, line: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        line.push_str(arg);
        return;
    }
    line.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                line.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                line.push('"');
                backslashes = 0;
            }
            _ => {
                line.extend(std::iter::repeat_n('\\', backslashes));
                line.push(c);
                backslashes = 0;
            }
        }
    }
    line.extend(std::iter::repeat_n('\\', backslashes * 2));
    line.push('"');
}

fn wide_nul(text: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain(Some(0)).collect()
}

/// The `PATH` the spawn sets, if it sets one.
fn path_of(envs: &[(String, String)]) -> Option<String> {
    envs.iter().rev().find(|(key, _)| key.eq_ignore_ascii_case("PATH")).map(|(_, value)| value.clone())
}

/// The program to run. A path (absolute, or relative to the current folder) runs `<path>.exe` when
/// that exists and the path does not end in `.exe`, else the path itself, as `std::process::Command`
/// does. A bare name is looked up the way it does too, never in the current folder: the spawn's
/// `PATH`, the system folders, then the app's `PATH`; `.exe` is added when it has no extension. A
/// bare name found nowhere fails with std's error (`NotFound`, "program not found").
pub fn resolve(program: &str, child_path: Option<&str>) -> io::Result<PathBuf> {
    let given = Path::new(program);
    if given.is_absolute() || given.components().count() > 1 {
        let has_exe = program.to_ascii_lowercase().ends_with(".exe");
        let with_exe = PathBuf::from(format!("{program}.exe"));
        return Ok(if !has_exe && with_exe.is_file() { with_exe } else { given.to_path_buf() });
    }
    let name = if given.extension().is_some() { program.to_string() } else { format!("{program}.exe") };
    let mut folders: Vec<PathBuf> = child_path.map(|path| std::env::split_paths(path).collect()).unwrap_or_default();
    folders.extend(system_folders());
    if let Some(path) = std::env::var_os("PATH") {
        folders.extend(std::env::split_paths(&path));
    }
    folders
        .into_iter()
        .filter(|folder| folder.is_absolute())
        .map(|folder| folder.join(&name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "program not found"))
}

fn system_folders() -> Vec<PathBuf> {
    let mut folders = Vec::new();
    for get in [GetSystemDirectoryW, GetWindowsDirectoryW] {
        let mut buffer = [0u16; 512];
        // SAFETY: the buffer holds 512 units.
        let len = unsafe { get(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if len > 0 && len < buffer.len() {
            use std::os::windows::ffi::OsStringExt;
            folders.push(PathBuf::from(OsString::from_wide(&buffer[..len])));
        }
    }
    folders
}

/// The app's environment with `envs` set over it (names compare without case, as Windows does),
/// sorted, as a double-NUL-terminated UTF-16 block.
fn environment_block(envs: &[(String, String)]) -> Vec<u16> {
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    for (key, value) in envs {
        vars.retain(|(existing, _)| !existing.eq_ignore_ascii_case(key));
        vars.push((key.into(), value.into()));
    }
    vars.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (key, value) in vars {
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

impl WinChild {
    fn raw(&self) -> HANDLE {
        self.process.as_raw_handle() as HANDLE
    }

    fn exit_status(&mut self) -> io::Result<ExitStatus> {
        let mut code = 0u32;
        // SAFETY: our process handle and a valid out-pointer.
        if unsafe { GetExitCodeProcess(self.raw(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = ExitStatus::from_raw(code);
        self.status = Some(status);
        Ok(status)
    }
}

impl ChildProcess for WinChild {
    fn id(&self) -> u32 {
        self.pid
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        // SAFETY: our process handle; a zero timeout only polls.
        match unsafe { WaitForSingleObject(self.raw(), 0) } {
            WAIT_OBJECT_0 => self.exit_status().map(Some),
            _ => Ok(None),
        }
    }

    /// Ends the process unless it already ended.
    fn kill(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // SAFETY: our process handle, which keeps the pid from being reused.
        if unsafe { TerminateProcess(self.raw(), 1) } == 0 {
            // SAFETY: no preconditions.
            let error = unsafe { GetLastError() };
            if self.try_wait()?.is_none() {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }
        Ok(())
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        // SAFETY: our process handle.
        if unsafe { WaitForSingleObject(self.raw(), INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        self.exit_status()
    }
}

/// The test binary doubles as a child process the tests start (`helper_spec`): it is this module's
/// ignored test `child_helper`, run alone, told what to do by `GENTLE_DOT_TEST_CHILD`. The daemon's
/// own handle test (`daemon::tests`) starts it too.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::daemon::LaunchSpec;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{GetHandleInformation, SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::Storage::FileSystem::{GetFileType, GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::CreateEventW;

    const MODE: &str = "GENTLE_DOT_TEST_CHILD";

    /// The test binary as a child, in `mode`: `inh` reports every inheritable handle it holds and
    /// what its stdio is ([`Inherited`]), `handle:<value>:<path>` reports whether the handle
    /// `<value>` is open on `<path>` in the child, `argv` prints the arguments it received after its
    /// own name, `stdio` prints a line on stdout and stderr, and `sleep` waits 30 s.
    pub(crate) fn helper_spec(mode: &str) -> LaunchSpec {
        LaunchSpec {
            program: std::env::current_exe().unwrap().display().to_string(),
            args: ["win_spawn::tests::child_helper", "--exact", "--ignored", "--nocapture", "--test-threads=1", "-q"]
                .map(String::from)
                .to_vec(),
            envs: vec![(MODE.into(), mode.into())],
        }
    }

    /// The path a handle is open on, if `handle` is an open file handle in this process.
    pub(crate) fn path_of_handle(handle: HANDLE) -> Option<String> {
        let mut buffer = [0u16; 1024];
        // SAFETY: the buffer holds 1024 units; an invalid handle fails.
        let len = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, FILE_NAME_NORMALIZED) };
        (len > 0 && (len as usize) < buffer.len()).then(|| String::from_utf16_lossy(&buffer[..len as usize]))
    }

    /// Every handle value in this process whose `HANDLE_FLAG_INHERIT` is set.
    pub(crate) fn inheritable_handles() -> Vec<usize> {
        (4..0x10_0000usize)
            .step_by(4)
            .filter(|&value| {
                let mut flags = 0u32;
                // SAFETY: a query on a handle value; one that is not open makes it fail.
                unsafe { GetHandleInformation(value as HANDLE, &mut flags) != 0 && flags & HANDLE_FLAG_INHERIT != 0 }
            })
            .collect()
    }

    /// Inheritable handles of the shapes a library of the app might leave: a file, both ends of an
    /// anonymous pipe, and an event. They close when dropped.
    pub(crate) fn plant(dir: &Path) -> Vec<OwnedHandle> {
        let file = File::create(dir.join("stray")).unwrap();
        let mut planted = vec![inheritable(borrow(&file)).unwrap()];
        let (mut read, mut write): (HANDLE, HANDLE) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: valid out-pointers; default security, not inheritable until set below.
        assert_ne!(unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) }, 0);
        // SAFETY: an unnamed manual-reset event with default security.
        let event = unsafe { CreateEventW(ptr::null(), TRUE, 0, ptr::null()) };
        assert!(!event.is_null());
        for handle in [read, write, event] {
            // SAFETY: handles just created here, owned from now on.
            let owned = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
            // SAFETY: our handle; only its inherit flag changes.
            assert_ne!(unsafe { SetHandleInformation(raw(&owned), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }, 0);
            planted.push(owned);
        }
        planted
    }

    /// What an `inh` child reported: its inheritable handles, and its stdio handles with stdin's
    /// file type and the path stdout is open on.
    #[derive(Debug)]
    pub(crate) struct Inherited {
        pub handles: Vec<usize>,
        pub stdin: usize,
        pub stdin_type: u32,
        pub stdout: usize,
        pub stdout_path: String,
        pub stderr: usize,
    }

    impl Inherited {
        pub(crate) fn parse(log: &str) -> Self {
            let field = |name: &str| -> Vec<&str> {
                let line = log.lines().find(|line| line.starts_with(&format!("{name} "))).unwrap_or_else(|| panic!("no {name}: {log}"));
                line[name.len() + 1..].splitn(2, ' ').collect()
            };
            let hex = |text: &str| usize::from_str_radix(text.trim_start_matches("0x"), 16).unwrap();
            let (stdin, stdout) = (field("stdin"), field("stdout"));
            Inherited {
                handles: field("inheritable").concat().split(',').filter(|v| !v.is_empty()).map(hex).collect(),
                stdin: hex(stdin[0]),
                stdin_type: stdin[1].parse().unwrap(),
                stdout: hex(stdout[0]),
                stdout_path: stdout.get(1).unwrap_or(&"").to_string(),
                stderr: hex(field("stderr")[0]),
            }
        }
    }

    #[test]
    #[ignore = "a child process the other tests start"]
    fn child_helper() {
        let Ok(mode) = std::env::var(MODE) else { return };
        match mode.as_str() {
            "stdio" => {
                println!("to stdout");
                eprintln!("to stderr");
            }
            "argv" => println!("argv {:?}", std::env::args_os().skip(1).collect::<Vec<_>>()),
            "inh" => {
                let handles: Vec<String> = inheritable_handles().iter().map(|value| format!("{value:#x}")).collect();
                let stdin = std::io::stdin().as_raw_handle() as HANDLE;
                let stdout = std::io::stdout().as_raw_handle() as HANDLE;
                println!("inheritable {}", handles.join(","));
                // SAFETY: a query on this process's stdin handle.
                println!("stdin {:#x} {}", stdin as usize, unsafe { GetFileType(stdin) });
                println!("stdout {:#x} {}", stdout as usize, path_of_handle(stdout).unwrap_or_default());
                println!("stderr {:#x}", std::io::stderr().as_raw_handle() as usize);
            }
            "sleep" => std::thread::sleep(Duration::from_secs(30)),
            probe => {
                let (value, path) = probe.strip_prefix("handle:").and_then(|rest| rest.split_once(':')).unwrap();
                let handle = value.parse::<usize>().unwrap() as HANDLE;
                let held = path_of_handle(handle).is_some_and(|open| open.eq_ignore_ascii_case(path));
                println!("probe {}", if held { "leaked" } else { "closed" });
            }
        }
    }

    /// A fresh folder for one test, removed by the test when it ends.
    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("gentle-dot-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(spec: &LaunchSpec, log: &File) -> WinChild {
        spawn(&Spawn { program: &spec.program, args: &spec.args, envs: &spec.envs }, log).unwrap()
    }

    #[test]
    fn stdout_and_stderr_go_to_the_log() {
        let dir = scratch("win-stdio");
        let log = File::create(dir.join("log")).unwrap();
        let mut child = run(&helper_spec("stdio"), &log);
        assert!(child.wait().unwrap().success());
        drop(log);
        let text = std::fs::read_to_string(dir.join("log")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(text.contains("to stdout") && text.contains("to stderr"), "{text}");
    }

    /// A handle some library of the app made inheritable, and what a child started each way sees.
    fn stray_reaches(by_std: bool) -> String {
        let dir = scratch(if by_std { "win-stray-std" } else { "win-stray" });
        let stray_file = File::create(dir.join("stray")).unwrap();
        let stray = inheritable(borrow(&stray_file)).unwrap();
        let path = path_of_handle(raw(&stray)).unwrap();
        let spec = helper_spec(&format!("handle:{}:{path}", raw(&stray) as usize));
        let log_path = dir.join("log");
        let log = File::create(&log_path).unwrap();
        if by_std {
            let status = std::process::Command::new(&spec.program)
                .args(&spec.args)
                .envs(spec.envs.iter().map(|(k, v)| (k, v)))
                .stdout(log.try_clone().unwrap())
                .status()
                .unwrap();
            assert!(status.success());
        } else {
            assert!(run(&spec, &log).wait().unwrap().success());
        }
        drop((stray, stray_file, log));
        let text = std::fs::read_to_string(log_path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        text
    }

    #[test]
    fn no_other_handle_of_the_app_reaches_the_child() {
        let text = stray_reaches(false);
        assert!(text.contains("probe closed"), "{text}");
    }

    #[test]
    fn the_stray_handle_probe_sees_a_leak_when_there_is_one() {
        // `std::process::Command` inherits every inheritable handle: the probe must see it.
        let text = stray_reaches(true);
        assert!(text.contains("probe leaked"), "{text}");
    }

    /// The `argv` line the child prints, started by `std::process::Command` or by `spawn`.
    fn argv_seen(spec: &LaunchSpec, by_std: bool) -> String {
        let dir = scratch(if by_std { "win-argv-std" } else { "win-argv" });
        let log_path = dir.join("log");
        let log = File::create(&log_path).unwrap();
        if by_std {
            let status = std::process::Command::new(&spec.program)
                .args(&spec.args)
                .envs(spec.envs.iter().map(|(k, v)| (k, v)))
                .stdout(log.try_clone().unwrap())
                .status()
                .unwrap();
            assert!(status.success());
        } else {
            assert!(run(spec, &log).wait().unwrap().success());
        }
        drop(log);
        let text = std::fs::read_to_string(&log_path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        text.lines().find(|line| line.starts_with("argv ")).unwrap_or_else(|| panic!("no argv line: {text}")).to_string()
    }

    /// The daemon's script path reaches the child exactly as `std::process::Command` hands it over:
    /// with spaces, quotes, trailing backslashes, and the verbatim prefix `build.rs` gives it.
    #[test]
    fn the_child_gets_the_same_arguments_std_gives_it() {
        let mut spec = helper_spec("argv");
        let verbatim = r"\\?\C:\gentle dot\packages\daemon\src\cli.ts";
        spec.args.extend([verbatim, r"C:\dir with space\", r#"say "hi""#, r"a\\b", "x\ty"].map(String::from));
        let ours = argv_seen(&spec, false);
        assert_eq!(ours, argv_seen(&spec, true));
        assert!(ours.contains(&format!("{verbatim:?}")), "{ours}");
    }

    /// End to end with the daemon's own runtime: Node, named bare as the dev launch names it, runs the
    /// script it is handed and sees that path un-mangled. Needs Node on PATH:
    /// `cargo test --lib a_node_child -- --ignored`.
    #[test]
    #[ignore = "needs Node on PATH"]
    fn a_node_child_gets_its_script_path_unmangled() {
        let dir = scratch("win-node argv");
        let script = dir.join("main.js");
        std::fs::write(&script, "console.log('node argv ' + JSON.stringify(process.argv.slice(1)))").unwrap();
        let script = script.display().to_string();
        let path = std::env::var("PATH").unwrap_or_default();
        let spec = LaunchSpec { program: "node".into(), args: vec![script.clone()], envs: vec![("PATH".into(), path)] };
        let log_path = dir.join("log");
        let log = File::create(&log_path).unwrap();
        let status = run(&spec, &log).wait().unwrap();
        drop(log);
        let text = std::fs::read_to_string(&log_path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(status.success(), "{text}");
        assert!(text.contains(&format!("node argv {}", serde_json::json!([script]))), "{text}");
    }

    #[test]
    fn kill_ends_a_running_child_and_try_wait_reports_it() {
        let dir = scratch("win-kill");
        let log = File::create(dir.join("log")).unwrap();
        let mut child = run(&helper_spec("sleep"), &log);
        assert!(child.try_wait().unwrap().is_none());
        let started = Instant::now();
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(child.try_wait().unwrap(), Some(status));
        // Killing an ended child is not an error.
        child.kill().unwrap();
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_program_that_does_not_exist_is_not_started() {
        let dir = scratch("win-missing");
        let log = File::create(dir.join("log")).unwrap();
        let spec = Spawn { program: "gentle-dot-no-such-program", args: &[], envs: &[] };
        let error = spawn(&spec, &log).unwrap_err();
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    /// A program named by a path without `.exe`, absolute or relative to the current folder, runs
    /// `<path>.exe`, as with `std::process::Command`.
    #[test]
    fn a_program_path_without_its_extension_runs_the_exe() {
        let absolute = std::env::current_exe().unwrap().with_extension("");
        let relative = absolute.strip_prefix(std::env::current_dir().unwrap()).expect("the test binary is under the current folder");
        for program in [absolute.as_path(), relative] {
            let mut spec = helper_spec("stdio");
            spec.program = program.display().to_string();
            let by_std = std::process::Command::new(&spec.program).args(&spec.args).envs(spec.envs.iter().map(|(k, v)| (k, v))).output();
            assert!(by_std.is_ok_and(|out| out.status.success()), "std runs {}", spec.program);
            let dir = scratch("win-no-ext");
            let log = File::create(dir.join("log")).unwrap();
            let ours = spawn(&Spawn { program: &spec.program, args: &spec.args, envs: &spec.envs }, &log).map(|mut child| child.wait());
            drop(log);
            let _ = std::fs::remove_dir_all(&dir);
            assert!(matches!(ours, Ok(Ok(status)) if status.success()), "{}: {ours:?}", spec.program);
        }
    }

    /// A program that is not there fails with the error `std::process::Command` gives, so the app's
    /// "cannot start" message reads as before.
    #[test]
    fn a_missing_program_fails_with_stds_error() {
        let dir = scratch("win-missing-std");
        let log = File::create(dir.join("log")).unwrap();
        let absolute = dir.join("missing.exe").display().to_string();
        for program in ["gentle-dot-no-such-program", absolute.as_str()] {
            let by_std = std::process::Command::new(program).spawn().unwrap_err();
            let ours = spawn(&Spawn { program, args: &[], envs: &[] }, &log).unwrap_err();
            assert_eq!((ours.kind(), ours.to_string()), (by_std.kind(), by_std.to_string()), "{program}");
        }
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bare_name_is_found_on_the_spawns_path_and_never_in_the_current_folder() {
        let dir = scratch("win-resolve");
        std::fs::write(dir.join("tool.exe"), b"").unwrap();
        let path = dir.display().to_string();
        assert_eq!(resolve("tool", Some(&path)).unwrap(), dir.join("tool.exe"));
        assert_eq!(resolve("tool.exe", Some(&path)).unwrap(), dir.join("tool.exe"));
        // A relative folder on PATH (the current folder, for one) is never searched.
        assert!(resolve("tool", Some(".")).is_err());
        assert!(resolve("cmd", None).unwrap().ends_with("cmd.exe"));
        assert_eq!(resolve(r"C:\x\y.exe", None).unwrap(), PathBuf::from(r"C:\x\y.exe"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn arguments_are_quoted_the_way_the_c_runtime_splits_them() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(command_line("node", &args(&["a", "b c", ""])), r#"node a "b c" """#);
        assert_eq!(command_line(r"C:\Program Files\node.exe", &[]), r#""C:\Program Files\node.exe""#);
        assert_eq!(command_line("x", &args(&[r#"say "hi""#])), r#"x "say \"hi\"""#);
        assert_eq!(command_line("x", &args(&[r"C:\dir with space\"])), r#"x "C:\dir with space\\""#);
        assert_eq!(command_line("x", &args(&[r"a\\b"])), r"x a\\b");
    }

    #[test]
    fn the_environment_is_the_apps_with_the_spawns_variables_over_it() {
        let block = environment_block(&[("Path".into(), r"C:\only".into()), ("GENTLE_DOT_X".into(), "1".into())]);
        let text = String::from_utf16_lossy(&block);
        let vars: Vec<&str> = text.split('\0').filter(|v| !v.is_empty()).collect();
        let paths: Vec<&&str> = vars.iter().filter(|v| v.to_uppercase().starts_with("PATH=")).collect();
        assert_eq!(paths, [&r"Path=C:\only"]);
        assert!(vars.contains(&"GENTLE_DOT_X=1"));
        assert!(block.ends_with(&[0, 0]));
        let keys: Vec<String> = vars.iter().map(|v| v.split('=').next().unwrap().to_uppercase()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}

