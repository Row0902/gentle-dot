//! Compile boundary only: native Windows daemon ownership is deferred to P02.
//! No process is started, probed, attached to, recorded, or stopped by this facade.

use crate::app_channel::{AppChannel, Handler};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const UNSUPPORTED: &str =
    "Unsupported: the native Windows assistant lifecycle and private channel are not implemented yet.";

/// Kept for the shell's existing restart outcome handling. This backend only returns Failed.
#[derive(Debug, PartialEq, Eq)]
pub enum RestartOutcome {
    Restarted,
    External,
    Failed(String),
}

/// Has no child, channel, PID record, or readiness callback to own.
pub struct Daemon;

impl Daemon {
    pub fn new(_port: u16, _data_dir: PathBuf, _runtime_dir: Option<PathBuf>) -> Self {
        Self
    }

    /// Accepts the shell interface without calling or retaining the service.
    pub fn with_channel(self, _handler: Arc<dyn Handler>) -> Self {
        self
    }

    /// An unsupported backend must never announce that the assistant is ready.
    pub fn on_ready(self, _ready: Arc<dyn Fn() + Send + Sync>) -> Self {
        self
    }

    pub fn channel(&self) -> Option<Arc<AppChannel>> {
        None
    }

    pub fn is_healthy(&self) -> bool {
        false
    }

    pub fn owns_running(&self) -> bool {
        false
    }

    pub fn refusal(&self) -> Option<String> {
        Some(UNSUPPORTED.into())
    }

    pub fn wait_ready(&self, _timeout: Duration) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }

    pub fn wait_healthy(&self, _timeout: Duration) -> bool {
        false
    }

    pub fn ensure_running(&self, _timeout: Duration) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }

    /// Harmless even when another daemon holds the configured port: nothing is owned.
    pub fn stop(&self) {}

    pub fn restart(&self, _timeout: Duration) -> RestartOutcome {
        RestartOutcome::Failed(UNSUPPORTED.into())
    }
}

/// Pure path selection, matching the existing shell contract; never inspects the filesystem.
pub fn runtime_dir(
    env: impl Fn(&str) -> Option<String>,
    resource_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    env("GENTLE_DOT_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| resource_dir.map(|dir| dir.join("runtime")))
}

/// Required by the shell's External branch; this facade never reports that outcome.
pub fn foreign_daemon_message(_port: u16) -> String {
    UNSUPPORTED.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::ApprovalRequest;
    use crate::secure_store::SecretStore;

    struct Untouched;

    impl Handler for Untouched {
        fn approve(&self, _: &ApprovalRequest) -> bool {
            panic!("unsupported daemon must not request approval")
        }

        fn opened(&self, _: &Arc<AppChannel>) {
            panic!("unsupported daemon must not open a channel")
        }

        fn secrets(&self) -> Option<&dyn SecretStore> {
            panic!("unsupported daemon must not access secrets")
        }
    }

    #[test]
    fn windows_daemon_start_and_restart_fail_with_or_without_channel() {
        for port in [0, 1, u16::MAX] {
            for wants_channel in [false, true] {
                // A facade must not inspect these paths or create logs/PID records there.
                let mut daemon = Daemon::new(port, PathBuf::new(), Some(PathBuf::new()));
                if wants_channel {
                    daemon = daemon.with_channel(Arc::new(Untouched));
                }
                let daemon = daemon.on_ready(Arc::new(|| panic!("must not announce readiness")));
                for timeout in [Duration::ZERO, Duration::MAX] {
                    assert_eq!(daemon.ensure_running(timeout), Err(UNSUPPORTED.into()));
                    assert_eq!(daemon.wait_ready(timeout), Err(UNSUPPORTED.into()));
                    assert!(!daemon.wait_healthy(timeout));
                    assert_eq!(
                        daemon.restart(timeout),
                        RestartOutcome::Failed(UNSUPPORTED.into())
                    );
                }
                assert_eq!(daemon.refusal(), Some(UNSUPPORTED.into()));
                assert!(!daemon.is_healthy());
                assert!(!daemon.owns_running());
                assert!(daemon.channel().is_none());
            }
        }
    }

    #[test]
    fn windows_daemon_stop_is_repeatable_and_owns_nothing() {
        let daemon = Daemon::new(1, PathBuf::new(), None);
        daemon.stop();
        daemon.stop();
        assert!(!daemon.owns_running());
        assert!(!daemon.is_healthy());
        assert!(daemon.channel().is_none());
        assert_eq!(
            daemon.ensure_running(Duration::ZERO),
            Err(UNSUPPORTED.into())
        );
    }

    #[test]
    fn windows_runtime_path_selection_does_not_require_a_runtime() {
        let resources = PathBuf::from("resources");
        assert_eq!(runtime_dir(|_| None, None), None);
        assert_eq!(
            runtime_dir(|_| None, Some(resources.clone())),
            Some(resources.join("runtime"))
        );
        assert_eq!(runtime_dir(|_| Some(String::new()), None), None);
        assert_eq!(
            runtime_dir(|_| Some("custom".into()), Some(resources)),
            Some(PathBuf::from("custom"))
        );
    }
}
