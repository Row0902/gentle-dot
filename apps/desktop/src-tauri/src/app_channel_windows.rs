//! Private Windows channel over owned stdio or verified named-pipe halves.
//! Duplex endpoints are authorized against the retained child's process identity.

use crate::approvals::ApprovalRequest;
use crate::isolated_bootstrap_windows::{PipeCancellation, PipeReader, PipeWriter};
use crate::owned_process_windows::ParentStdio;
use crate::secure_store::{check_id, Secret, SecretStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{GetCurrentThreadId, OpenThread, THREAD_TERMINATE};

// Unix and Windows occupy the same mutually exclusive module path, so these
// wire definitions cannot be imported from the Unix implementation.
const MAX_FRAME: usize = 1024 * 1024;
const TOO_LARGE: &str = "too large to send to the assistant";
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(150);
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(60);
pub const NO_CHANNEL: &str =
    "Gentle Dot did not start this assistant, so its connectors cannot be changed from here. \
Quit the assistant that is running and open Gentle Dot again.";
pub const PANEL_COMMANDS: &[&str] = &[
    "connector_connect",
    "connector_signin",
    "connector_setup",
    "connector_disconnect",
    "connector_remove",
    "connector_mode",
    "connector_draft_reply",
    "connector_import",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Frame {
    Request {
        id: u64,
        method: String,
        #[serde(default)]
        params: Value,
    },
    Response {
        id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

pub fn is_panel_command(message: &Value) -> bool {
    message
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| PANEL_COMMANDS.contains(&kind))
}

pub trait Handler: Send + Sync {
    fn approve(&self, request: &ApprovalRequest) -> bool;
    fn opened(&self, _channel: &Arc<AppChannel>) {}
    fn secrets(&self) -> Option<&dyn SecretStore> {
        None
    }
}

#[derive(Debug)]
enum Delivery {
    Closed,
    Sent(io::Result<()>),
    Answer(Result<Value, String>),
}
type Reply = mpsc::Sender<Delivery>;

// At most 16 queued 1-MiB frames, one in flight, and 64 pending replies.
const MAX_QUEUED: usize = 16;
const MAX_PENDING: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Transmission {
    Queued,
    Writing,
    Sent,
    Expired,
}

#[derive(Debug)]
struct Outgoing {
    line: Vec<u8>,
    deadline: Instant,
    state: Arc<Mutex<Transmission>>,
    completed: Option<Reply>,
}

#[derive(Debug)]
enum ChannelReader {
    Stdio(File),
    Duplex(PipeReader),
}

impl ChannelReader {
    // None means an idle stdio pipe; Some(0) means duplex EOF.
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self {
            Self::Duplex(reader) => reader.read(buffer).map(Some),
            Self::Stdio(reader) => {
                let mut available = 0;
                // Only the owning reader thread consumes this live pipe.
                if unsafe {
                    PeekNamedPipe(
                        reader.as_raw_handle(),
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                if available == 0 {
                    return Ok(None);
                }
                let count = buffer.len().min(available as usize);
                reader.read(&mut buffer[..count]).map(Some)
            }
        }
    }
}

enum ChannelWriter {
    Stdio(File),
    Duplex(PipeWriter),
}

impl ChannelWriter {
    fn write_all(&mut self, buffer: &[u8]) -> io::Result<()> {
        match self {
            Self::Stdio(writer) => writer.write_all(buffer),
            Self::Duplex(writer) => writer.write_all(buffer),
        }
    }
}

#[derive(Debug)]
pub struct AppChannel {
    outgoing: Mutex<VecDeque<Outgoing>>,
    wake_writer: Condvar,
    reader: Mutex<Option<ChannelReader>>,
    writing_thread: Mutex<Option<u32>>,
    duplex_cancellation: Mutex<Option<(PipeCancellation, PipeCancellation)>>,
    pending: Mutex<HashMap<u64, Reply>>,
    next: AtomicU64,
    open: AtomicBool,
}

// The legacy stdio path uses thread-scoped synchronous cancellation;
// the duplex path instead targets its own registered OVERLAPPED operations.
#[link(name = "kernel32")]
extern "system" {
    fn CancelSynchronousIo(thread: windows_sys::Win32::Foundation::HANDLE) -> i32;
}

impl AppChannel {
    /// Starts the reader for pipe ends returned by the crate's owned process.
    pub(crate) fn start(pipes: ParentStdio, handler: Arc<dyn Handler>) -> io::Result<Arc<Self>> {
        Self::start_transport(
            ChannelReader::Stdio(pipes.stdout),
            ChannelWriter::Stdio(pipes.stdin),
            None,
            handler,
        )
    }

    /// Starts the channel on independently cancellable, verified duplex halves.
    pub(crate) fn start_duplex(
        reader: PipeReader,
        writer: PipeWriter,
        handler: Arc<dyn Handler>,
    ) -> io::Result<Arc<Self>> {
        let cancellation = (reader.cancellation(), writer.cancellation());
        Self::start_transport(
            ChannelReader::Duplex(reader),
            ChannelWriter::Duplex(writer),
            Some(cancellation),
            handler,
        )
    }

    fn start_transport(
        reader: ChannelReader,
        writer: ChannelWriter,
        cancellation: Option<(PipeCancellation, PipeCancellation)>,
        handler: Arc<dyn Handler>,
    ) -> io::Result<Arc<Self>> {
        let channel = Arc::new(Self {
            outgoing: Mutex::new(VecDeque::new()),
            wake_writer: Condvar::new(),
            reader: Mutex::new(Some(reader)),
            writing_thread: Mutex::new(None),
            duplex_cancellation: Mutex::new(cancellation),
            pending: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
            open: AtomicBool::new(true),
        });
        let writing = channel.clone();
        std::thread::Builder::new()
            .name("app-channel-writer".into())
            .spawn(move || writing.transmit(writer))?;
        let reading = channel.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("app-channel".into())
            .spawn(move || reading.read(handler))
        {
            channel.close();
            return Err(error);
        }
        Ok(channel)
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Reply>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        let deadline = Instant::now() + timeout;
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (reply, answer) = mpsc::channel();
        {
            let mut pending = self.pending();
            if !self.is_open() {
                return Err("The assistant's channel is closed.".into());
            }
            if pending.len() >= MAX_PENDING {
                return Err("The assistant's channel is busy.".into());
            }
            pending.insert(id, reply.clone());
        }
        let transmission = self.enqueue(
            &Frame::Request {
                id,
                method: method.into(),
                params,
            },
            deadline,
            Some(reply),
        );
        if let Err(error) = &transmission {
            self.pending().remove(&id);
            if error.kind() == io::ErrorKind::InvalidInput {
                return Err(format!("This request is {TOO_LARGE}."));
            }
            if !self.is_open() {
                return Err("The assistant's channel is closed.".into());
            }
            return Err(format!("The assistant could not be reached: {error}"));
        }
        let result = Self::receive(&answer, deadline);
        self.pending().remove(&id);
        match result {
            Ok(answer) => answer,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.expire(&transmission.unwrap());
                Err("The assistant did not answer in time.".into())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("The assistant's channel is closed.".into())
            }
        }
    }

    fn receive(
        answer: &mpsc::Receiver<Delivery>,
        deadline: Instant,
    ) -> Result<Result<Value, String>, mpsc::RecvTimeoutError> {
        let mut sent = false;
        let mut response = None;
        loop {
            // A populated receiver can satisfy even a zero-duration recv_timeout.
            // Expiry must not depend on the peer leaving the event queue empty.
            let now = Instant::now();
            if now >= deadline {
                return Err(mpsc::RecvTimeoutError::Timeout);
            }
            let event = answer.recv_timeout(deadline.duration_since(now));
            // Deadline wins a delivery race, including already-queued completion.
            if Instant::now() >= deadline {
                return Err(mpsc::RecvTimeoutError::Timeout);
            }
            match event {
                Ok(Delivery::Sent(Ok(()))) => sent = true,
                Ok(Delivery::Sent(Err(_))) => {
                    break Ok(Err("The assistant's channel is closed.".into()))
                }
                Ok(Delivery::Closed) => break Ok(Err("The assistant's channel is closed.".into())),
                Ok(Delivery::Answer(answer)) => response = Some(answer),
                Err(error) => break Err(error),
            }
            if sent && response.is_some() {
                break Ok(response.take().unwrap());
            }
        }
    }

    pub fn command(&self, client_id: &str, message: Value) -> Result<(), String> {
        if !is_panel_command(&message) {
            return Err("Only connector changes go through the app.".into());
        }
        self.request(
            "command",
            json!({"clientId":client_id,"message":message}),
            COMMAND_TIMEOUT,
        )
        .map(|_| ())
    }

    pub fn close(&self) {
        self.open.store(false, Ordering::SeqCst);
        for (_, reply) in self.pending().drain() {
            let _ = reply.send(Delivery::Closed);
        }
        self.outgoing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.wake_writer.notify_all();
        // Take the revocation handles so a retained closed channel does not
        // retain the pipe. Workers keep their I/O storage until settlement.
        let cancellation = self
            .duplex_cancellation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some((reader, writer)) = cancellation {
            let _ = reader.cancel();
            let _ = writer.cancel();
        }
        // No reader lock, join or cancellation-completion wait on the caller.
        // The stdio reader retries synchronous writer cancellation on shutdown.
        self.cancel_write();
    }

    fn cancel_write(&self) -> bool {
        let writing = self
            .writing_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(id) = *writing else {
            return false;
        };
        // SAFETY: the identity guard prevents clearing the id or thread exit
        // during OpenThread/cancellation. This worker performs no unrelated I/O.
        unsafe {
            let thread = OpenThread(THREAD_TERMINATE, 0, id);
            if !thread.is_null() {
                CancelSynchronousIo(thread);
                CloseHandle(thread);
            }
        }
        true
    }

    fn expire(&self, state: &Mutex<Transmission>) {
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        let writing = *state == Transmission::Writing;
        if *state != Transmission::Sent {
            *state = Transmission::Expired;
        }
        // Revoke before permitting any later frame after potentially partial I/O.
        if writing {
            self.close();
        }
    }

    fn enqueue(
        &self,
        frame: &Frame,
        deadline: Instant,
        completed: Option<Reply>,
    ) -> io::Result<Arc<Mutex<Transmission>>> {
        let mut line = serde_json::to_vec(frame).map_err(io::Error::other)?;
        if line.len() > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, TOO_LARGE));
        }
        line.push(b'\n');
        let mut queue = self.outgoing.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.is_open() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"));
        }
        if queue.len() >= MAX_QUEUED {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "channel busy"));
        }
        let state = Arc::new(Mutex::new(Transmission::Queued));
        queue.push_back(Outgoing {
            line,
            deadline,
            state: state.clone(),
            completed,
        });
        self.wake_writer.notify_one();
        Ok(state)
    }

    fn write(&self, frame: &Frame) -> io::Result<()> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let (tx, rx) = mpsc::channel();
        let state = self.enqueue(frame, deadline, Some(tx))?;
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Delivery::Sent(result)) => result,
            Ok(Delivery::Closed | Delivery::Answer(_)) => unreachable!("write-only completion"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.expire(&state);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "channel write timed out",
                ))
            }
            Err(_) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")),
        }
    }

    fn transmit(self: Arc<Self>, mut writer: ChannelWriter) {
        let synchronous = matches!(&writer, ChannelWriter::Stdio(_));
        loop {
            let outgoing = {
                let mut queue = self.outgoing.lock().unwrap_or_else(PoisonError::into_inner);
                while queue.is_empty() && self.is_open() {
                    queue = self
                        .wake_writer
                        .wait(queue)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                if !self.is_open() {
                    return;
                }
                queue.pop_front().unwrap()
            };
            {
                let mut state = outgoing
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if *state == Transmission::Expired || Instant::now() >= outgoing.deadline {
                    continue;
                }
                *state = Transmission::Writing;
                if synchronous {
                    *self
                        .writing_thread
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) =
                        Some(unsafe { GetCurrentThreadId() });
                }
            }
            let result = if self.is_open() {
                writer.write_all(&outgoing.line)
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
            };
            // Clear identity only after synchronous I/O has actually completed.
            self.writing_thread
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let mut state = outgoing
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if result.is_err()
                || *state == Transmission::Expired
                || Instant::now() >= outgoing.deadline
            {
                self.close();
            } else {
                *state = Transmission::Sent;
            }
            if let Some(completed) = outgoing.completed {
                let _ = completed.send(Delivery::Sent(result));
            }
        }
    }

    fn read(self: Arc<Self>, handler: Arc<dyn Handler>) {
        let mut line = Vec::new();
        let mut buffer = [0u8; 8192];
        // Stdio retains peek-before-read polling. Duplex reads can block here:
        // close uses the independent cancellation handle, never the reader lock.
        'reading: while self.is_open() {
            let result = {
                let mut reader = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(reader) = reader.as_mut() else {
                    break;
                };
                reader.receive(&mut buffer)
            };
            match result {
                Err(_) | Ok(Some(0)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Ok(Some(count)) => {
                    for &byte in &buffer[..count] {
                        line.push(byte);
                        if line.len() > MAX_FRAME + 1 {
                            break 'reading;
                        }
                        if byte == b'\n' {
                            match serde_json::from_slice::<Frame>(&line) {
                                Ok(Frame::Response { id, result, error }) => {
                                    if let Some(reply) = self.pending().get(&id) {
                                        let _ = reply.send(Delivery::Answer(match error {
                                            Some(error) => Err(error),
                                            None => Ok(result.unwrap_or(Value::Null)),
                                        }));
                                    }
                                }
                                Ok(Frame::Request { id, method, params }) => {
                                    let (channel, handler) = (self.clone(), handler.clone());
                                    if std::thread::Builder::new()
                                        .name("app-channel-request".into())
                                        .spawn(move || {
                                            channel.answer(id, &method, params, handler.as_ref())
                                        })
                                        .is_err()
                                    {
                                        // Never park the reader/cancellation monitor on a write.
                                        let _ = self.enqueue(&Frame::Response {
                                            id,
                                            result: None,
                                            error: Some("busy".into()),
                                        }, Instant::now() + COMMAND_TIMEOUT, None);
                                    }
                                }
                                Err(_) => eprintln!(
                                    "gentle-dot: the assistant's channel sent a frame that is not understood"
                                ),
                            }
                            line.clear();
                        } else if line.len() == MAX_FRAME + 1 {
                            break 'reading;
                        }
                    }
                }
            }
        }
        self.close();
        self.reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        // Retry covers cancellation racing entry into WriteFile. If the OS
        // refuses cancellation, isolated writer/monitor resources survive until
        // peer disconnect; caller deadlines and close do not wait for them.
        while self.cancel_write() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn answer(&self, id: u64, method: &str, params: Value, handler: &dyn Handler) {
        let answer = match method {
            "approve" => Ok(
                json!({"approved":serde_json::from_value::<ApprovalRequest>(params)
                .is_ok_and(|request| handler.approve(&request))}),
            ),
            "secret_get" | "secret_put" | "secret_delete" | "secret_list" => {
                match handler.secrets() {
                    Some(store) => serve_secret(store, method, &params),
                    None => Err("This app has no secure store for connector secrets.".into()),
                }
            }
            other => Err(format!("Unknown request: {other}")),
        };
        let frame = match answer {
            Ok(result) => Frame::Response {
                id,
                result: Some(result),
                error: None,
            },
            Err(error) => Frame::Response {
                id,
                result: None,
                error: Some(error),
            },
        };
        if self
            .write(&frame)
            .is_err_and(|error| error.kind() == io::ErrorKind::InvalidInput)
        {
            let _ = self.write(&Frame::Response {
                id,
                result: None,
                error: Some(format!("The answer is {TOO_LARGE}.")),
            });
        }
    }
}

fn serve_secret(store: &dyn SecretStore, method: &str, params: &Value) -> Result<Value, String> {
    if method == "secret_list" {
        return store
            .list_ids()
            .map(|ids| json!({"ids":ids}))
            .map_err(|error| error.to_string());
    }
    let id = params
        .get("id")
        .and_then(Value::as_str)
        .ok_or("A secret request needs an id.")?;
    check_id(id).map_err(|error| error.to_string())?;
    let secret = match params.get("secret") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(Secret::new(text)),
        Some(_) => return Err("A secret must be text.".into()),
    };
    match method {
        "secret_get" => Ok(store
            .get(id)
            .map_err(|error| error.to_string())?
            .map(|secret| json!({"secret":secret.expose()}))
            .unwrap_or(Value::Null)),
        "secret_put" => {
            store
                .put(id, secret.as_ref().ok_or("A secret to store is needed.")?)
                .map_err(|error| error.to_string())?;
            Ok(json!({}))
        }
        "secret_delete" => {
            Ok(json!({"deleted":store.delete(id).map_err(|error| error.to_string())?}))
        }
        other => Err(format!("Unknown request: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owned_process_windows::OwnedProcess;
    use crate::secure_store::{MemoryStore, StoreError, MAX_ID_LEN};

    fn duplex_peer(role: &str) -> (OwnedProcess, PipeReader, PipeWriter) {
        use crate::isolated_bootstrap_windows::ServerEndpoint;
        use std::ffi::OsString;
        let server = ServerEndpoint::create().unwrap();
        let process = OwnedProcess::spawn(
            std::env::current_exe().unwrap().as_os_str(),
            &[
                OsString::from("--exact"),
                OsString::from("app_channel::tests::windows_channel_duplex_fixture"),
                OsString::from("--nocapture"),
            ],
            &[
                (
                    OsString::from("CHANNEL_PIPE"),
                    OsString::from(server.name()),
                ),
                (OsString::from("CHANNEL_TEST_ROLE"), OsString::from(role)),
            ],
        )
        .unwrap();
        let endpoint = server
            .accept_owned(
                process.retained_identity().unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        let (reader, writer) = endpoint.into_duplex().unwrap();
        (process, reader, writer)
    }

    fn duplex_fixture(role: &str) -> (OwnedProcess, Arc<AppChannel>, mpsc::Receiver<String>) {
        let (process, reader, writer) = duplex_peer(role);
        let (tx, rx) = mpsc::channel();
        let channel = AppChannel::start_duplex(reader, writer, Arc::new(Approver(tx))).unwrap();
        (process, channel, rx)
    }

    #[test]
    fn windows_channel_duplex_fixture_accepts_both_approval_orders() {
        use std::io::BufRead;
        for request_first in [true, false] {
            let (mut process, reader, mut writer) = duplex_peer("echo-approve");
            let cancel = reader.cancellation();
            let (tx, rx) = mpsc::channel();
            let reading = std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(reader);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                tx.send(serde_json::from_str::<Value>(&line).unwrap())
                    .unwrap();
                line.clear();
                reader.read_line(&mut line).unwrap();
                tx.send(serde_json::from_str::<Value>(&line).unwrap())
                    .unwrap();
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let approval = rx.recv_timeout(Duration::from_secs(3)).unwrap();
                assert_eq!(approval["kind"], "request");
                assert_eq!(approval["id"], 90);
                let request = json!({"kind":"request","id":1,"method":"echo","params":{"value":7}});
                let response = json!({"kind":"response","id":90,"result":{"approved":true}});
                let frames = if request_first {
                    [&request, &response]
                } else {
                    [&response, &request]
                };
                for frame in frames {
                    writeln!(writer, "{frame}").unwrap();
                }
                rx.recv_timeout(Duration::from_secs(3))
            }));
            // Bound cleanup even when the child rejects the interleaving.
            let _ = cancel.cancel();
            let exit = process.wait(3000).unwrap();
            process.stop().unwrap();
            let joined = reading.join();
            assert_eq!(
                result.unwrap().unwrap(),
                json!({"kind":"response","id":1,"result":{"value":7}})
            );
            assert_eq!(exit, Some(0));
            joined.unwrap();
        }
    }

    #[test]
    fn windows_channel_duplex_fixture() {
        use std::io::BufRead;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
        };
        let Ok(name) = std::env::var("CHANNEL_PIPE") else {
            return;
        };
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let mut writer = unsafe { File::from_raw_handle(handle) };
        let mut reader = std::io::BufReader::new(writer.try_clone().unwrap());
        let role = std::env::var("CHANNEL_TEST_ROLE").unwrap();
        if role == "no-read" {
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        let mut queued = VecDeque::new();
        if role == "echo-approve" {
            writeln!(writer, "{}", json!({"kind":"request","id":90,"method":"approve","params":{"connector":"Slack","action":"send","preview":[]}})).unwrap();
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                let frame: Value = serde_json::from_str(&line).unwrap();
                // Parent requests can precede the approval response: the handler
                // notifies the parent before its answer is queued for transmission.
                if frame["kind"] == "request" {
                    queued.push_back(frame);
                    continue;
                }
                assert_eq!(frame["kind"], "response");
                assert_eq!(frame["id"], 90);
                assert_eq!(frame["result"], json!({"approved":true}));
                break;
            }
        }
        loop {
            let frame = if let Some(frame) = queued.pop_front() {
                frame
            } else {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    return;
                }
                serde_json::from_str::<Value>(&line).unwrap()
            };
            assert_eq!(frame["kind"], "request");
            if role == "hold" {
                continue;
            }
            writeln!(
                writer,
                "{}",
                json!({"kind":"response","id":frame["id"],"result":frame["params"]})
            )
            .unwrap();
            return;
        }
    }

    fn workers_released(channel: &Arc<AppChannel>) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Arc::strong_count(channel) != 1 {
            assert!(
                Instant::now() < deadline,
                "channel workers retained resources after close"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn windows_channel_duplex_round_trip_approval_and_eof() {
        let (mut process, channel, approvals) = duplex_fixture("echo-approve");
        assert_eq!(
            approvals.recv_timeout(Duration::from_secs(5)).unwrap(),
            "app-channel-request"
        );
        let result = channel.request("echo", json!({"value":7}), Duration::from_secs(5));
        let exit = process.wait(5000).unwrap();
        process.stop().unwrap();
        assert_eq!(result, Ok(json!({"value":7})));
        assert_eq!(exit, Some(0));
        workers_released(&channel);
        assert!(!channel.is_open());
    }

    #[test]
    fn windows_channel_duplex_timeout_and_blocked_reader_close() {
        let (mut process, channel, _) = duplex_fixture("hold");
        assert_eq!(
            channel.request("echo", Value::Null, Duration::from_millis(100)),
            Err("The assistant did not answer in time.".into())
        );
        assert!(
            channel.is_open(),
            "response timeout revoked a usable transport"
        );
        let started = Instant::now();
        channel.close();
        let elapsed = started.elapsed();
        // Prove workers release while peer is still alive, not because stop unblocks I/O.
        workers_released(&channel);
        process.stop().unwrap();
        assert!(elapsed < Duration::from_secs(1));
        assert!(!channel.is_open());
    }

    #[test]
    fn windows_channel_duplex_stalled_write_deadline_releases_workers() {
        let (mut process, channel, _) = duplex_fixture("no-read");
        let started = Instant::now();
        let result = channel.request(
            "echo",
            Value::String("x".repeat(900_000)),
            Duration::from_millis(200),
        );
        let elapsed = started.elapsed();
        let revoked = !channel.is_open();
        workers_released(&channel);
        process.stop().unwrap();
        assert_eq!(result, Err("The assistant did not answer in time.".into()));
        assert!(revoked);
        assert!(elapsed < Duration::from_secs(1));
    }

    fn fixture(role: &str) -> (OwnedProcess, ParentStdio) {
        use std::ffi::OsString;
        OwnedProcess::spawn_with_stdio(
            std::env::current_exe().unwrap().as_os_str(),
            &[
                OsString::from("--exact"),
                OsString::from("app_channel::tests::windows_channel_fixture"),
                OsString::from("--nocapture"),
            ],
            &[(OsString::from("CHANNEL_TEST_ROLE"), OsString::from(role))],
        )
        .unwrap()
    }

    #[test]
    fn windows_channel_fixture() {
        use std::io::BufRead;
        let Ok(role) = std::env::var("CHANNEL_TEST_ROLE") else {
            return;
        };
        if role == "exit" {
            std::process::exit(0);
        }
        if role == "no-read" {
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        let mut reader = std::io::BufReader::new(std::io::stdin());
        if role == "concurrent" {
            println!(
                "{}",
                json!({"kind":"request","id":90,"method":"approve","params":{"connector":"Slack","action":"send","preview":[]}})
            );
            std::io::stdout().flush().unwrap();
            let mut requests = Vec::new();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let frame: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(frame["kind"], "request");
                requests.push(frame);
            }
            assert_ne!(requests[0]["id"], requests[1]["id"]);
            for frame in requests.into_iter().rev() {
                println!(
                    "{}",
                    json!({"kind":"response","id":frame["id"],"result":frame["params"]})
                );
            }
            std::io::stdout().flush().unwrap();
            // App requests and the approval response may interleave. Only answer
            // the final probe after the fixture has verified the approval response.
            let mut queued = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let frame: Value = serde_json::from_str(&line).unwrap();
                if frame["kind"] == "request" {
                    queued.push(frame);
                } else {
                    assert_eq!(frame["id"], 90);
                    assert_eq!(frame["result"], json!({"approved":true}));
                    break;
                }
            }
            for frame in queued {
                println!(
                    "{}",
                    json!({"kind":"response","id":frame["id"],"result":frame["params"]})
                );
            }
            std::io::stdout().flush().unwrap();
        }
        if role == "approve" {
            println!(
                "{}",
                json!({"kind":"request","id":90,"method":"approve","params":{"connector":"Slack","action":"send","preview":[]}})
            );
            std::io::stdout().flush().unwrap();
            let mut queued = Vec::new();
            let answer = loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let frame: Value = serde_json::from_str(&line).unwrap();
                if frame["kind"] == "request" {
                    queued.push(frame);
                } else {
                    break frame;
                }
            };
            assert_eq!(answer["id"], 90);
            assert_eq!(answer["result"], json!({"approved":true}));
            for frame in queued {
                assert_eq!(frame["method"], "echo");
                println!(
                    "{}",
                    json!({"kind":"response","id":frame["id"],"result":frame["params"]})
                );
            }
            std::io::stdout().flush().unwrap();
        }
        if role == "garbage" {
            println!("not JSON");
        }
        if role == "refusals" {
            let mut queued = Vec::new();
            for (id, method, params) in [
                (1, "approve", json!({"connector":5})),
                (2, "unknown", Value::Null),
                (3, "secret_get", json!({"id":"test/id"})),
            ] {
                println!(
                    "{}",
                    json!({"kind":"request","id":id,"method":method,"params":params})
                );
                std::io::stdout().flush().unwrap();
                let answer = loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let frame: Value = serde_json::from_str(&line).unwrap();
                    if frame["kind"] == "request" {
                        queued.push(frame);
                    } else {
                        break frame;
                    }
                };
                assert_eq!(answer["id"], id);
                if method == "approve" {
                    assert_eq!(answer["result"], json!({"approved":false}));
                } else {
                    assert!(answer["error"].is_string());
                }
            }
            // The app's request can interleave with daemon-initiated requests.
            // Answer it only after all refusal responses have been checked.
            for frame in queued {
                assert_eq!(frame["method"], "echo");
                println!(
                    "{}",
                    json!({"kind":"response","id":frame["id"],"result":frame["params"]})
                );
            }
            std::io::stdout().flush().unwrap();
        }
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                std::process::exit(0);
            }
            let frame: Value = serde_json::from_str(&line).unwrap();
            if role == "hold" {
                println!(
                    "{}",
                    json!({"kind":"request","id":999,"method":"approve","params":{"connector":"Slack","action":"received","preview":[]}})
                );
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
            assert_eq!(frame["method"], "echo");
            if role.starts_with("incoming-") {
                let mut bytes = serde_json::to_vec(&json!({
                    "kind":"response","id":frame["id"],"result":""
                }))
                .unwrap();
                let size = if role == "incoming-boundary" {
                    MAX_FRAME
                } else {
                    MAX_FRAME + 1
                };
                let padding = size - bytes.len();
                // Insert padding inside the empty JSON result string.
                let position = bytes.len() - 2;
                bytes.splice(position..position, std::iter::repeat_n(b'x', padding));
                if role != "incoming-unterminated" {
                    bytes.push(b'\n');
                }
                std::io::stdout().write_all(&bytes).unwrap();
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(60));
                std::process::exit(0);
            }
            println!(
                "{}",
                json!({"kind":"response","id":frame["id"],"result":frame["params"]})
            );
            std::io::stdout().flush().unwrap();
        }
    }

    // The watchdog owns only this fixture. Even the original blocked write is
    // released after three seconds, so a behavioral RED cannot hang the runner.
    fn deadline_regression(queued: bool) {
        let (ready, started_fixture) = mpsc::channel();
        let (release, cleanup) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            let (mut process, channel) = live("no-read");
            ready.send(channel).unwrap();
            let _ = cleanup.recv_timeout(Duration::from_secs(3));
            process.stop().unwrap();
            assert!(process.wait(5000).unwrap().is_some());
        });
        let channel = started_fixture
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let first = if queued {
            Some(std::thread::spawn({
                let channel = channel.clone();
                move || {
                    channel.request(
                        "echo",
                        Value::String("x".repeat(900_000)),
                        Duration::from_secs(10),
                    )
                }
            }))
        } else {
            None
        };
        if queued {
            let limit = std::time::Instant::now() + Duration::from_secs(2);
            while channel.writing_thread.lock().unwrap().is_none() {
                assert!(std::time::Instant::now() < limit, "writer never started");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let started = std::time::Instant::now();
        let result = channel.request(
            "echo",
            if queued {
                Value::Null
            } else {
                Value::String("x".repeat(900_000))
            },
            Duration::from_millis(200),
        );
        let elapsed = started.elapsed();
        let revoked = !channel.is_open();
        if !queued {
            assert!(channel
                .request("echo", Value::Null, Duration::from_millis(200))
                .unwrap_err()
                .contains("closed"));
        }
        let _ = release.send(());
        watchdog.join().unwrap();
        if let Some(first) = first {
            assert!(first.join().unwrap().is_err());
        }
        channel.close();
        assert!(
            elapsed < Duration::from_secs(1),
            "deadline exceeded: {elapsed:?}; result={result:?}"
        );
        assert_eq!(result, Err("The assistant did not answer in time.".into()));
        if !queued {
            assert!(
                revoked,
                "partial transmission was not revoked at the deadline"
            );
        }
    }

    #[test]
    fn windows_channel_deadline_populated_receiver() {
        // This is the production request receive loop, not a test of std alone.
        // Finite preloading deterministically models duplicate matching Answers
        // while transmission is stalled, without an unbounded flood or cleanup.
        let (tx, rx) = mpsc::channel();
        for _ in 0..1024 {
            tx.send(Delivery::Answer(Ok(Value::Null))).unwrap();
        }
        let expired = Instant::now() - Duration::from_millis(1);
        assert_eq!(
            AppChannel::receive(&rx, expired),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        assert!(
            rx.try_recv().is_ok(),
            "expired request drained the Answer backlog"
        );

        // Even both completion events cannot turn an expired request into success.
        let (tx, rx) = mpsc::channel();
        tx.send(Delivery::Sent(Ok(()))).unwrap();
        tx.send(Delivery::Answer(Ok(Value::Null))).unwrap();
        assert_eq!(
            AppChannel::receive(&rx, expired),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        // Either valid transfer/response ordering is accepted before the deadline.
        for reversed in [false, true] {
            let (tx, rx) = mpsc::channel();
            let events = if reversed {
                [Delivery::Answer(Ok(json!(7))), Delivery::Sent(Ok(()))]
            } else {
                [Delivery::Sent(Ok(())), Delivery::Answer(Ok(json!(7)))]
            };
            for event in events {
                tx.send(event).unwrap();
            }
            assert_eq!(
                AppChannel::receive(&rx, Instant::now() + Duration::from_secs(1)),
                Ok(Ok(json!(7)))
            );
        }
    }

    #[test]
    fn windows_channel_deadline_stalled_transmission() {
        deadline_regression(false);
    }

    #[test]
    fn windows_channel_deadline_queued_transmission() {
        deadline_regression(true);
    }

    #[test]
    fn windows_channel_incoming_frame_bounds() {
        for role in [
            "incoming-oversized",
            "incoming-unterminated",
            "incoming-boundary",
        ] {
            let (_process, channel) = live(role);
            let result = channel.request("echo", Value::Null, Duration::from_secs(5));
            if role == "incoming-boundary" {
                let value = result.unwrap();
                let frame = Frame::Response {
                    id: 1,
                    result: Some(value),
                    error: None,
                };
                assert_eq!(serde_json::to_vec(&frame).unwrap().len(), MAX_FRAME);
                assert!(channel.is_open());
            } else {
                assert!(result.unwrap_err().contains("closed"));
                assert!(!channel.is_open());
            }
            channel.close();
        }
    }

    struct Approver(mpsc::Sender<String>);

    impl Handler for Approver {
        fn approve(&self, _: &ApprovalRequest) -> bool {
            self.0
                .send(std::thread::current().name().unwrap_or("").to_owned())
                .unwrap();
            true
        }
    }

    fn live(role: &str) -> (OwnedProcess, Arc<AppChannel>) {
        let (process, pipes) = fixture(role);
        let (tx, _) = mpsc::channel();
        (
            process,
            AppChannel::start(pipes, Arc::new(Approver(tx))).unwrap(),
        )
    }

    #[test]
    fn windows_channel_round_trip() {
        let (_process, channel) = live("echo");
        assert_eq!(
            channel.request("echo", json!({"value":7}), Duration::from_secs(5)),
            Ok(json!({"value":7}))
        );
        channel.close();
    }

    #[test]
    fn windows_channel_approval_worker() {
        let (process, pipes) = fixture("approve");
        let (tx, rx) = mpsc::channel();
        let channel = AppChannel::start(pipes, Arc::new(Approver(tx))).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "app-channel-request"
        );
        assert_eq!(
            channel.request(
                "echo",
                json!({"approved_response_observed":true}),
                Duration::from_secs(5)
            ),
            Ok(json!({"approved_response_observed":true}))
        );
        channel.close();
        assert_eq!(process.wait(5000).unwrap(), Some(0));
    }

    #[test]
    fn windows_channel_oversize_not_written() {
        let (_process, channel) = live("echo");
        assert!(channel
            .request(
                "oversize",
                Value::String("x".repeat(MAX_FRAME)),
                Duration::from_secs(5)
            )
            .unwrap_err()
            .contains("too large"));
        assert!(channel.is_open());
        assert_eq!(
            channel.request("echo", Value::Null, Duration::from_secs(5)),
            Ok(Value::Null)
        );
        channel.close();
    }

    #[test]
    fn windows_channel_close_wakes_request() {
        let (_process, pipes) = fixture("hold");
        let (tx, rx) = mpsc::channel();
        let channel = AppChannel::start(pipes, Arc::new(Approver(tx))).unwrap();
        let waiting = std::thread::spawn({
            let channel = channel.clone();
            move || channel.request("echo", Value::Null, Duration::from_secs(30))
        });
        // The fixture asks only after consuming the app's request, so this is
        // genuinely waiting for a reply, not just a thread scheduled after close.
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        channel.close();
        channel.close();
        assert!(waiting.join().unwrap().unwrap_err().contains("closed"));
        assert!(!channel.is_open());
    }

    #[test]
    fn windows_channel_exit_observed() {
        let (process, channel) = live("exit");
        assert_eq!(process.wait(5000).unwrap(), Some(0));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while channel.is_open() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!channel.is_open());
    }

    #[test]
    fn windows_channel_garbage_ignored() {
        let (_process, channel) = live("garbage");
        assert_eq!(
            channel.request("echo", Value::Null, Duration::from_secs(5)),
            Ok(Value::Null)
        );
        channel.close();
    }

    #[test]
    fn windows_channel_blocked_write_cancelled() {
        let (mut process, channel) = live("no-read");
        let waiting = std::thread::spawn({
            let channel = channel.clone();
            move || {
                channel.request(
                    "echo",
                    Value::String("x".repeat(900_000)),
                    Duration::from_secs(30),
                )
            }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let writing = channel.writing_thread.lock().unwrap();
            let active = writing.is_some();
            drop(writing);
            if active {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "writer never started");
            std::thread::sleep(Duration::from_millis(1));
        }
        let (tx, rx) = mpsc::channel();
        let closing = std::thread::spawn({
            let channel = channel.clone();
            move || {
                channel.close();
                tx.send(()).unwrap();
            }
        });
        let closed = rx.recv_timeout(Duration::from_secs(5));
        // Stop only our owned fixture even on failure, to release any blocked I/O.
        process.stop().unwrap();
        assert!(closed.is_ok(), "close did not cancel the pipe write");
        closing.join().unwrap();
        assert!(waiting.join().unwrap().unwrap_err().contains("closed"));
    }

    #[test]
    fn windows_channel_refuses_bad_requests() {
        let (process, channel) = live("refusals");
        assert_eq!(
            channel.request("echo", Value::Null, Duration::from_secs(5)),
            Ok(Value::Null)
        );
        channel.close();
        assert_eq!(process.wait(5000).unwrap(), Some(0));
    }

    #[test]
    fn windows_channel_timeout() {
        let (_process, channel) = live("no-read");
        let started = std::time::Instant::now();
        assert_eq!(
            channel.request("echo", Value::Null, Duration::from_millis(100)),
            Err("The assistant did not answer in time.".into())
        );
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(channel.pending().is_empty());
        channel.close();
    }

    #[test]
    fn windows_channel_secrets_memory_round_trip() {
        let store = MemoryStore::new();
        let ask = |method: &str, params: Value| serve_secret(&store, method, &params).unwrap();
        assert_eq!(ask("secret_get", json!({"id":"test/missing"})), Value::Null);
        assert_eq!(
            ask(
                "secret_put",
                json!({"id":"test/b","secret":"synthetic-value"})
            ),
            json!({})
        );
        assert_eq!(
            ask("secret_get", json!({"id":"test/b"})),
            json!({"secret":"synthetic-value"})
        );
        assert_eq!(
            ask("secret_put", json!({"id":"test/b","secret":"replacement"})),
            json!({})
        );
        assert_eq!(
            ask("secret_get", json!({"id":"test/b"})),
            json!({"secret":"replacement"})
        );
        assert_eq!(
            ask("secret_put", json!({"id":"test/a","secret":""})),
            json!({})
        );
        assert_eq!(
            ask("secret_list", Value::Null),
            json!({"ids":["test/a","test/b"]})
        );
        assert_eq!(
            ask("secret_delete", json!({"id":"test/b"})),
            json!({"deleted":true})
        );
        assert_eq!(
            ask("secret_delete", json!({"id":"test/b"})),
            json!({"deleted":false})
        );
        assert_eq!(ask("secret_get", json!({"id":"test/b"})), Value::Null);
        assert_eq!(ask("secret_list", Value::Null), json!({"ids":["test/a"]}));
    }

    #[test]
    fn windows_channel_secrets_invalid_input_is_redacted() {
        let store = MemoryStore::new();
        for id in [
            "".to_owned(),
            "has space".into(),
            "line\nfeed".into(),
            "x".repeat(MAX_ID_LEN + 1),
        ] {
            for method in ["secret_get", "secret_put", "secret_delete"] {
                let error = serve_secret(
                    &store,
                    method,
                    &json!({"id":id,"secret":"synthetic-private-value"}),
                )
                .unwrap_err();
                assert_eq!(error, "invalid secret id");
                assert!(!error.contains("synthetic-private-value"));
            }
        }
        for params in [
            Value::Null,
            json!({"secret":"synthetic-private-value"}),
            json!({"id":42}),
        ] {
            assert_eq!(
                serve_secret(&store, "secret_put", &params),
                Err("A secret request needs an id.".into())
            );
        }
        for secret in [
            json!(true),
            json!(123456789),
            json!([]),
            json!({"value":"synthetic-private-value"}),
        ] {
            assert_eq!(
                serve_secret(
                    &store,
                    "secret_put",
                    &json!({"id":"test/id","secret":secret})
                ),
                Err("A secret must be text.".into())
            );
        }
        for params in [
            json!({"id":"test/id"}),
            json!({"id":"test/id","secret":null}),
        ] {
            assert_eq!(
                serve_secret(&store, "secret_put", &params),
                Err("A secret to store is needed.".into())
            );
        }
        assert!(store.list_ids().unwrap().is_empty());
    }

    // An in-memory test double only; no OS store or production fallback is used.
    struct FailingStore;

    impl SecretStore for FailingStore {
        fn put(&self, _: &str, _: &Secret) -> Result<(), StoreError> {
            Err(StoreError::Denied)
        }
        fn get(&self, _: &str) -> Result<Option<Secret>, StoreError> {
            Err(StoreError::NotText)
        }
        fn delete(&self, _: &str) -> Result<bool, StoreError> {
            Err(StoreError::Failed("synthetic delete failure".into()))
        }
        fn list_ids(&self) -> Result<Vec<String>, StoreError> {
            Err(StoreError::Unavailable("synthetic list failure".into()))
        }
    }

    #[test]
    fn windows_channel_secrets_store_failures_are_static() {
        for (method, expected) in [
            ("secret_put", "access to the secret store was denied"),
            ("secret_get", "the stored secret is not text"),
            (
                "secret_delete",
                "the secret store failed: synthetic delete failure",
            ),
            (
                "secret_list",
                "the secret store is unavailable: synthetic list failure",
            ),
        ] {
            let error = serve_secret(
                &FailingStore,
                method,
                &json!({"id":"test/id","secret":"synthetic-private-value"}),
            )
            .unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.contains("synthetic-private-value"));
        }
    }

    struct BlockingApprover {
        entered: mpsc::Sender<String>,
        release: Mutex<mpsc::Receiver<()>>,
        finished: AtomicBool,
    }

    impl Handler for BlockingApprover {
        fn approve(&self, _: &ApprovalRequest) -> bool {
            self.entered
                .send(std::thread::current().name().unwrap_or("").into())
                .unwrap();
            // Sender drop on a failed test also releases this worker. No sleep
            // controls ordering, and even an unreleased handler has a deadline.
            let approved = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(15))
                .is_ok();
            self.finished.store(true, Ordering::SeqCst);
            approved
        }
    }

    #[test]
    fn windows_channel_reader_progresses_during_blocked_approval() {
        let (process, pipes) = fixture("concurrent");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let handler = Arc::new(BlockingApprover {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            finished: AtomicBool::new(false),
        });
        let channel = AppChannel::start(pipes, handler.clone()).unwrap();
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "app-channel-request"
        );
        let requests: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|label| {
                let channel = channel.clone();
                std::thread::spawn(move || {
                    let params = json!({"label":label});
                    assert_eq!(
                        channel.request("echo", params.clone(), Duration::from_secs(5)),
                        Ok(params)
                    );
                })
            })
            .collect();
        for request in requests {
            request.join().unwrap();
        }
        // Both reverse-order replies were matched by id while approve was blocked.
        assert!(!handler.finished.load(Ordering::SeqCst));
        release_tx.send(()).unwrap();
        assert_eq!(
            channel.request(
                "echo",
                json!({"approval_observed":true}),
                Duration::from_secs(5)
            ),
            Ok(json!({"approval_observed":true}))
        );
        assert!(handler.finished.load(Ordering::SeqCst));
        channel.close();
        assert_eq!(process.wait(5000).unwrap(), Some(0));
    }

    #[test]
    fn windows_channel_panel_gate_and_closed_requests() {
        let (_process, channel) = live("echo");
        assert!(channel
            .command("window", json!({"type":"send"}))
            .unwrap_err()
            .contains("Only connector"));
        channel.close();
        channel.close();
        assert!(channel
            .request("echo", Value::Null, Duration::ZERO)
            .unwrap_err()
            .contains("closed"));
    }
}
