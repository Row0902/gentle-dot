//! Fail-closed Windows facade. No transport or authenticated channel exists yet.
//! Handler compatibility does not authorize approvals or access to connector secrets.

use crate::approvals::ApprovalRequest;
use crate::secure_store::SecretStore;
use serde_json::Value;
use std::io;
use std::sync::Arc;
use std::time::Duration;

pub const NO_CHANNEL: &str =
    "Unsupported: the native Windows private assistant channel is not implemented yet.";
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(60);

/// Compatible with the shell's service, but never invoked by this backend.
pub trait Handler: Send + Sync {
    fn approve(&self, request: &ApprovalRequest) -> bool;
    fn opened(&self, _channel: &Arc<AppChannel>) {}
    fn secrets(&self) -> Option<&dyn SecretStore> {
        None
    }
}

/// An inert facade, not a live grant. Its private field prevents caller construction.
/// There is deliberately no Unix fd constant or placeholder Windows transport handle.
#[derive(Debug)]
pub struct AppChannel {
    _private: (),
}

impl AppChannel {
    /// Fails before invoking the handler; a Windows transport API is deferred to P03.
    pub fn start(_handler: Arc<dyn Handler>) -> io::Result<Arc<Self>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, NO_CHANNEL))
    }

    pub fn is_open(&self) -> bool {
        false
    }

    pub fn request(
        &self,
        _method: &str,
        _params: Value,
        _timeout: Duration,
    ) -> Result<Value, String> {
        Err(NO_CHANNEL.into())
    }

    pub fn command(&self, _client_id: &str, _message: Value) -> Result<(), String> {
        Err(NO_CHANNEL.into())
    }

    /// Owns no transport, worker thread, or pending request.
    pub fn close(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Untouched;

    impl Handler for Untouched {
        fn approve(&self, _: &ApprovalRequest) -> bool {
            panic!("unsupported backend must not request approval")
        }

        fn opened(&self, _: &Arc<AppChannel>) {
            panic!("unsupported backend must not announce a channel")
        }

        fn secrets(&self) -> Option<&dyn SecretStore> {
            panic!("unsupported backend must not access secrets")
        }
    }

    #[test]
    fn windows_channel_start_is_unsupported_without_handler_calls() {
        let error = AppChannel::start(Arc::new(Untouched)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), NO_CHANNEL);
    }

    #[test]
    fn windows_channel_operations_remain_closed_and_fail() {
        // Only module-local tests can construct this inert facade, never a live grant.
        let channel = AppChannel { _private: () };
        for method in [
            "approve",
            "secret_get",
            "secret_put",
            "secret_delete",
            "secret_list",
            "computer_register",
        ] {
            assert_eq!(
                channel.request(method, Value::Null, Duration::ZERO),
                Err(NO_CHANNEL.into())
            );
        }
        for message in [
            serde_json::json!({"type": "connector_connect"}),
            Value::Null,
        ] {
            assert_eq!(channel.command("window", message), Err(NO_CHANNEL.into()));
        }
        channel.close();
        channel.close();
        assert!(!channel.is_open());
        assert!(channel
            .request("command", Value::Null, Duration::MAX)
            .is_err());
    }
}
