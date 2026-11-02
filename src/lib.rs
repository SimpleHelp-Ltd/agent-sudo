pub mod execution;
pub mod maintenance;
pub mod protocol;
pub mod security;
pub mod store;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const HELPER: &str = "/usr/local/libexec/agent-sudo-helper";
pub const FRONTEND: &str = "/usr/local/bin/agent-sudo";
pub const CONTROL: &str = "/var/lib/agent-sudo";
pub const RUNTIME: &str = "/run/agent-sudo";
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn fail<T>(s: &str) -> Result<T> {
    Err(s.to_owned().into())
}
