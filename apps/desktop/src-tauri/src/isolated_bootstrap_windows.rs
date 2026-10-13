//! Restricted endpoint creation and retained-process peer identity matching.
#![allow(dead_code)] // Not wired into production until the later bootstrap units.

use super::owned_process_windows::RetainedIdentity;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};
use std::{io, ptr};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, SystemServices::SE_GROUP_LOGON_ID, Threading::*},
};

const PREFIX: &str = r"\\.\pipe\gentle-dot-";
// Client opens require FILE_READ_ATTRIBUTES against this restrictive DACL.
const CLIENT_RIGHTS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const OPEN_MODE: u32 = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
const PIPE_MODE: u32 = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn checked(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn random_name() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{PREFIX}{suffix}"))
}

// Pointer-aligned storage keeps TOKEN_GROUPS and its inline SID storage alive together.
struct LogonGroups(Vec<usize>);
impl LogonGroups {
    fn current() -> io::Result<Self> {
        unsafe {
            let mut token = ptr::null_mut();
            checked(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            ))?;
            let token = Handle(token);
            let mut needed = 0;
            let result = GetTokenInformation(token.0, TokenGroups, ptr::null_mut(), 0, &mut needed);
            if result != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
                return Err(io::Error::other("unexpected TokenGroups sizing result"));
            }
            let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
            checked(GetTokenInformation(
                token.0,
                TokenGroups,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ))?;
            let groups = Self(storage);
            groups.sid()?; // Missing or ambiguous logon SID fails closed.
            Ok(groups)
        }
    }

    fn sid(&self) -> io::Result<PSID> {
        unsafe {
            let groups = &*(self.0.as_ptr() as *const TOKEN_GROUPS);
            let entries =
                std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
            let mut logon = entries.iter().filter(|group| {
                group.Attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32
            });
            match (logon.next(), logon.next()) {
                (Some(group), None) if IsValidSid(group.Sid) != 0 => Ok(group.Sid),
                _ => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unique logon SID unavailable",
                )),
            }
        }
    }
}

struct ServerEndpoint {
    handle: Handle,
    name: String,
}
impl ServerEndpoint {
    fn create() -> io::Result<Self> {
        Self::create_named(random_name()?)
    }

    // Private implementation detail; only tests inject a name, never callers.
    fn create_named(name: String) -> io::Result<Self> {
        let groups = LogonGroups::current()?;
        unsafe {
            let mut sid_text = ptr::null_mut();
            checked(ConvertSidToStringSidW(groups.sid()?, &mut sid_text))?;
            let _owned_sid_text = LocalAllocation(sid_text.cast());
            let mut length = 0;
            while *sid_text.add(length) != 0 {
                length += 1;
            }
            let sid_text = String::from_utf16(std::slice::from_raw_parts(sid_text, length))
                .map_err(io::Error::other)?;
            // Protected DACL, exactly one allow ACE. No generic-write alias:
            // bit 0x4 is FILE_CREATE_PIPE_INSTANCE, not a client write permission.
            // The owner can still receive implicit READ_CONTROL/WRITE_DAC rights;
            // this does not resist same-user tampering or authenticate a peer.
            let sddl = wide(&format!("D:P(A;;0x{CLIENT_RIGHTS:x};;;{sid_text})"));
            let mut descriptor = ptr::null_mut();
            checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            ))?;
            let _owned_descriptor = LocalAllocation(descriptor);
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let name_wide = wide(&name);
            // The descriptor/ACL/SID buffers remain alive until Windows copies
            // them during this call. No operation is queued on this handle.
            let handle = CreateNamedPipeW(
                name_wide.as_ptr(),
                OPEN_MODE,
                PIPE_MODE,
                1,
                4096,
                4096,
                0,
                &attributes,
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                handle: Handle(handle),
                name,
            })
        }
    }

    fn accept_owned(
        self,
        identity: RetainedIdentity,
        deadline: Instant,
    ) -> io::Result<VerifiedEndpoint> {
        identity.live_pid()?;
        let Self { handle, name: _ } = self;
        let raw = handle.0;
        std::mem::forget(handle);
        let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("bootstrap-authorize".into())
            .spawn(move || {
                let result = authorize_operation(pipe, &identity, deadline);
                let _ = sender.send(result);
            })?;
        let result = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| timed_out())?;
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        result
    }

    fn connect_unverified(self, deadline: Instant) -> io::Result<UnverifiedEndpoint> {
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        // Transfer only a safe owned handle, not the raw-pointer wrapper, to one
        // operation owner. The caller never joins cancellation cleanup.
        let Self { handle, name: _ } = self;
        let raw = handle.0;
        std::mem::forget(handle);
        let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("bootstrap-connect".into())
            .spawn(move || {
                let result = connect_operation(pipe, deadline, None);
                // Failed delivery drops the private endpoint, including a late result.
                let _ = sender.send(result);
            })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = receiver.recv_timeout(remaining).map_err(|_| timed_out())?;
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        result
    }

    #[cfg(test)]
    fn same_name_for_test(name: &str) -> io::Result<Self> {
        Self::create_named(name.to_owned())
    }
}

// No channel operations or handle accessor: connection is not authorization.
struct UnverifiedEndpoint {
    pipe: OwnedHandle,
}
impl Drop for UnverifiedEndpoint {
    fn drop(&mut self) {
        unsafe {
            DisconnectNamedPipe(self.pipe.as_raw_handle());
        }
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "bootstrap connection deadline")
}

// Matches the retained live OS process, not a secret or compromise-resistant authentication.
// Deliberately exposes no protocol or read/write operations.
struct VerifiedEndpoint {
    _endpoint: UnverifiedEndpoint,
}

fn authorize_operation(
    mut pipe: OwnedHandle,
    identity: &RetainedIdentity,
    deadline: Instant,
) -> io::Result<VerifiedEndpoint> {
    loop {
        identity.live_pid()?;
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        let endpoint = connect_operation(pipe, deadline, Some(identity))?;
        let mut client_pid = 0;
        checked(unsafe {
            GetNamedPipeClientProcessId(endpoint.pipe.as_raw_handle(), &mut client_pid)
        })?;
        if client_pid == identity.live_pid()? {
            return Ok(VerifiedEndpoint {
                _endpoint: endpoint,
            });
        }
        // Retain a duplicate for the next accept; dropping the rejected endpoint
        // disconnects the same pipe instance before that accept begins.
        pipe = endpoint.pipe.try_clone()?;
        drop(endpoint);
    }
}

fn connect_operation(
    pipe: OwnedHandle,
    deadline: Instant,
    identity: Option<&RetainedIdentity>,
) -> io::Result<UnverifiedEndpoint> {
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
    operation.hEvent = event.as_raw_handle();
    let raw = pipe.as_raw_handle();
    let connected = unsafe { ConnectNamedPipe(raw, &mut operation) };
    if connected == 0 {
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => {}
            ERROR_IO_PENDING => {
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let failure = identity
                        .and_then(|identity| identity.live_pid().err())
                        .or_else(|| remaining.is_zero().then(timed_out));
                    if let Some(error) = failure {
                        // CancelIoEx requests cancellation; it does NOT settle it.
                        // This worker keeps stack OVERLAPPED, event, and pipe alive
                        // until GetOverlappedResult actually reports completion.
                        unsafe {
                            CancelIoEx(raw, &operation);
                        }
                        let mut transferred = 0;
                        unsafe {
                            GetOverlappedResult(raw, &operation, &mut transferred, 1);
                        }
                        return Err(error);
                    }
                    let millis = remaining.min(Duration::from_millis(10)).as_millis().max(1) as u32;
                    match unsafe { WaitForSingleObject(event.as_raw_handle(), millis) } {
                        WAIT_OBJECT_0 => {
                            let mut transferred = 0;
                            checked(unsafe {
                                GetOverlappedResult(raw, &operation, &mut transferred, 1)
                            })?;
                            break;
                        }
                        WAIT_TIMEOUT => {}
                        _ => {
                            let error = io::Error::last_os_error();
                            unsafe {
                                CancelIoEx(raw, &operation);
                            }
                            let mut transferred = 0;
                            unsafe {
                                GetOverlappedResult(raw, &operation, &mut transferred, 1);
                            }
                            return Err(error);
                        }
                    }
                }
            }
            _ => return Err(io::Error::last_os_error()),
        }
    }
    let endpoint = UnverifiedEndpoint { pipe };
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(role: &str, name: &str) -> super::super::owned_process_windows::OwnedProcess {
        use std::ffi::OsString;
        super::super::owned_process_windows::OwnedProcess::spawn(
            std::env::current_exe().unwrap().as_os_str(),
            &[
                OsString::from("--exact"),
                OsString::from("isolated_bootstrap_windows::tests::windows_bootstrap_peer_fixture"),
            ],
            &[
                ("BOOTSTRAP_ROLE".into(), role.into()),
                ("BOOTSTRAP_PIPE".into(), name.into()),
            ],
        )
        .unwrap()
    }

    #[test]
    fn windows_bootstrap_peer_fixture() {
        let Ok(role) = std::env::var("BOOTSTRAP_ROLE") else {
            return;
        };
        if role == "exit" {
            return;
        }
        if role == "waiting-exit" {
            std::thread::sleep(Duration::from_millis(200));
            return;
        }
        let name = wide(&std::env::var("BOOTSTRAP_PIPE").unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    CLIENT_RIGHTS,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                let _handle = Handle(handle);
                std::thread::sleep(Duration::from_secs(5));
                return;
            }
            assert!(Instant::now() < deadline, "{}", io::Error::last_os_error());
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn windows_bootstrap_owned_correct() {
        let server = ServerEndpoint::create().unwrap();
        let process = peer("connect", &server.name);
        assert!(server
            .accept_owned(
                process.retained_identity().unwrap(),
                Instant::now() + Duration::from_secs(5)
            )
            .is_ok());
    }

    #[test]
    fn windows_bootstrap_owned_wrong_first() {
        let server = ServerEndpoint::create().unwrap();
        let wrong = peer("connect", &server.name);
        // Observe the connected PID before starting the owned client: no ordering sleep.
        let start = Instant::now();
        loop {
            let mut pid = 0;
            if unsafe { GetNamedPipeClientProcessId(server.handle.0, &mut pid) } != 0 {
                assert_eq!(pid, wrong.retained_identity().unwrap().live_pid().unwrap());
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        let process = peer("connect", &server.name);
        assert!(server
            .accept_owned(
                process.retained_identity().unwrap(),
                start + Duration::from_secs(5)
            )
            .is_ok());
    }

    #[test]
    fn windows_bootstrap_owned_dead() {
        let server = ServerEndpoint::create().unwrap();
        let process = peer("exit", &server.name);
        assert!(process.wait(5000).unwrap().is_some());
        let start = Instant::now();
        let error = server
            .accept_owned(
                process.retained_identity().unwrap(),
                start + Duration::from_secs(5),
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "owned peer exited");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn windows_bootstrap_owned_waiting_exit() {
        let server = ServerEndpoint::create().unwrap();
        let process = peer("waiting-exit", &server.name);
        let identity = process.retained_identity().unwrap();
        identity.live_pid().unwrap();
        let start = Instant::now();
        let error = server
            .accept_owned(identity, start + Duration::from_secs(5))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "owned peer exited");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn windows_bootstrap_connection_zero_deadline() {
        let endpoint = ServerEndpoint::create().unwrap();
        let error = endpoint
            .connect_unverified(std::time::Instant::now())
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn windows_bootstrap_connection_pending_timeout() {
        let endpoint = ServerEndpoint::create().unwrap();
        let start = std::time::Instant::now();
        let error = endpoint
            .connect_unverified(start + std::time::Duration::from_millis(100))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn windows_bootstrap_connection_early_client() {
        let endpoint = ServerEndpoint::create().unwrap();
        let name = wide(&endpoint.name);
        // Connection-only fixture: no data rights and no protocol bytes.
        let client = unsafe {
            CreateFileW(
                name.as_ptr(),
                0,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            client,
            INVALID_HANDLE_VALUE,
            "{}",
            io::Error::last_os_error()
        );
        let _client = Handle(client);
        assert!(endpoint
            .connect_unverified(std::time::Instant::now() + std::time::Duration::from_secs(5))
            .is_ok());
    }

    #[test]
    fn windows_bootstrap_endpoint_missing_logon_sid_fails_closed() {
        let groups = LogonGroups(vec![
            0usize;
            size_of::<TOKEN_GROUPS>().div_ceil(size_of::<usize>())
        ]);
        assert_eq!(
            groups.sid().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn windows_bootstrap_endpoint_random_names() {
        let a = random_name().unwrap();
        let b = random_name().unwrap();
        assert_ne!(a, b);
        for name in [a, b] {
            let suffix = name.strip_prefix(PREFIX).unwrap();
            assert_eq!(suffix.len(), 32);
            assert!(suffix
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        }
    }

    #[test]
    fn windows_bootstrap_endpoint_collision_and_drop() {
        let endpoint = ServerEndpoint::create().unwrap();
        let name = endpoint.name.clone();
        let error = ServerEndpoint::same_name_for_test(&name)
            .err()
            .expect("collision must fail");
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
        drop(endpoint);
        let recreated = ServerEndpoint::same_name_for_test(&name).unwrap();
        assert_eq!(recreated.name, name);
    }

    #[test]
    fn windows_bootstrap_endpoint_handle_and_policy() {
        let endpoint = ServerEndpoint::create().unwrap();
        unsafe {
            let mut flags = 0;
            checked(GetHandleInformation(endpoint.handle.0, &mut flags)).unwrap();
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            let mut pipe_flags = 0;
            let mut instances = 0;
            checked(GetNamedPipeInfo(
                endpoint.handle.0,
                &mut pipe_flags,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut instances,
            ))
            .unwrap();
            assert_eq!(pipe_flags & PIPE_TYPE_MESSAGE, 0);
            assert_eq!(instances, 1);
        }
        // GetNamedPipeInfo documents only type/server flags, not remote rejection.
        // This checks the actual creation parameter, not remote-network behavior.
        assert_ne!(PIPE_MODE & PIPE_REJECT_REMOTE_CLIENTS, 0);
        assert_ne!(OPEN_MODE & FILE_FLAG_OVERLAPPED, 0);
        assert_ne!(OPEN_MODE & FILE_FLAG_FIRST_PIPE_INSTANCE, 0);
    }

    #[test]
    fn windows_bootstrap_endpoint_actual_dacl() {
        let endpoint = ServerEndpoint::create().unwrap();
        let groups = LogonGroups::current().unwrap();
        unsafe {
            let mut acl = ptr::null_mut();
            let mut sd = ptr::null_mut();
            let result = GetSecurityInfo(
                endpoint.handle.0,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut sd,
            );
            let _owned_sd = LocalAllocation(sd);
            assert_eq!(result, ERROR_SUCCESS);
            assert!(!sd.is_null());
            let mut control = 0;
            let mut revision = 0;
            checked(GetSecurityDescriptorControl(
                sd,
                &mut control,
                &mut revision,
            ))
            .unwrap();
            assert_ne!(control & SE_DACL_PRESENT, 0);
            assert_ne!(control & SE_DACL_PROTECTED, 0);
            assert!(!acl.is_null());
            assert_eq!((*acl).AceCount, 1);
            let mut ace = ptr::null_mut();
            checked(GetAce(acl, 0, &mut ace)).unwrap();
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            assert_eq!(allowed.Header.AceType, 0); // ACCESS_ALLOWED_ACE_TYPE
            assert_eq!(allowed.Header.AceFlags, 0);
            assert_eq!(allowed.Mask, CLIENT_RIGHTS);
            assert_eq!(allowed.Mask & FILE_CREATE_PIPE_INSTANCE, 0);
            assert_ne!(
                EqualSid(
                    ptr::addr_of!(allowed.SidStart) as PSID,
                    groups.sid().unwrap()
                ),
                0
            );
        }
    }
}
