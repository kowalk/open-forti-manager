use crate::config::VpnProfile;

/// Current state of the VPN connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error(String),
}

impl ConnectionState {
    pub fn label(&self) -> &str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::Connecting => "Connecting\u{2026}",
            ConnectionState::Connected => "Connected",
            ConnectionState::Disconnecting => "Disconnecting\u{2026}",
            ConnectionState::Error(_) => "Error",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Connecting | ConnectionState::Connected)
    }
}

// ---------------------------------------------------------------------------
// VpnBackend trait — the abstraction the UI drives. The only implementation is
// the native engine (`engine::backend::NativeVpnBackend`).
// ---------------------------------------------------------------------------

pub trait VpnBackend {
    fn connect(&mut self, profile: &VpnProfile) -> Result<(), String>;
    fn disconnect(&mut self) -> Result<(), String>;
    fn check_status(&mut self);
    fn state(&self) -> &ConnectionState;
    fn drain_log(&mut self) -> Vec<String>;
}
