//! Creation only: no connection, pending I/O, process launch, or peer authentication.
#![allow(dead_code)] // Not wired into production until the later bootstrap units.

use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, SystemServices::SE_GROUP_LOGON_ID, Threading::*},
};

const PREFIX: &str = r"\\.\pipe\gentle-dot-";
const CLIENT_RIGHTS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE;
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

    #[cfg(test)]
    fn same_name_for_test(name: &str) -> io::Result<Self> {
        Self::create_named(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
