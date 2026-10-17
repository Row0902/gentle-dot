pub mod alert;
#[cfg(not(target_os = "windows"))]
pub mod app_channel;
#[cfg(target_os = "windows")]
#[path = "app_channel_windows.rs"]
pub mod app_channel;
pub mod approvals;
pub mod computer;
pub mod config;
#[cfg(not(target_os = "windows"))]
pub mod daemon;
#[cfg(target_os = "windows")]
#[path = "daemon_windows.rs"]
pub mod daemon;
#[cfg(target_os = "macos")]
pub mod disclaimed;
pub mod geometry;
pub mod health;
#[cfg(target_os = "windows")]
mod isolated_bootstrap_windows;
#[cfg(target_os = "windows")]
mod owned_process_windows;
pub mod platform;
pub mod position;
pub mod secure_store;
mod shell;
pub mod shortcut;
pub mod status;
pub mod voice;

pub use shell::run;
