use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single VPN connection profile consumed by the native SSL-VPN engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnProfile {
    /// Display name for this profile
    pub name: String,
    /// VPN gateway hostname or IP
    pub host: String,
    /// VPN gateway port (default: 443)
    pub port: Option<u16>,
    /// VPN account username
    pub username: String,
    /// VPN account password (stored in config file — consider keyring in future)
    pub password: Option<String>,
    /// Path to custom CA certificate bundle (PEM)
    pub ca_file: Option<String>,
    /// Path to user certificate (PEM) for client authentication
    pub user_cert: Option<String>,
    /// Path to user private key (PEM)
    pub user_key: Option<String>,
    /// Trusted certificate digest (SHA256)
    pub trusted_cert: Option<String>,
    /// Use SAML authentication (--saml-login)
    pub saml_login: Option<bool>,
    /// SAML HTTP server port (default: 8020)
    pub saml_port: Option<u16>,
    /// Override DNS settings (--set-dns)
    pub set_dns: Option<bool>,
    /// Configure routes (--set-routes)
    pub set_routes: Option<bool>,
    /// Use half-internet routes instead of default route
    pub half_internet_routes: Option<bool>,
    /// Authentication realm
    pub realm: Option<String>,
}

impl VpnProfile {
    /// Create a new profile with sensible defaults.
    pub fn new(name: &str, host: &str, username: &str) -> Self {
        Self {
            name: name.to_string(),
            host: host.to_string(),
            port: None,
            username: username.to_string(),
            password: None,
            ca_file: None,
            user_cert: None,
            user_key: None,
            trusted_cert: None,
            saml_login: None,
            saml_port: None,
            set_dns: None,
            set_routes: None,
            half_internet_routes: None,
            realm: None,
        }
    }

}

/// Global application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Minimize to system tray instead of closing
    pub minimize_to_tray: bool,
    /// Minimize the window after a successful connection
    #[serde(default)]
    pub minimize_after_connect: bool,
    /// Start with the main window hidden (only tray visible)
    pub start_minimized: bool,
    /// Name of the profile to auto-connect on startup
    pub auto_connect_profile: Option<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            minimize_to_tray: true,
            minimize_after_connect: false,
            start_minimized: false,
            auto_connect_profile: None,
        }
    }
}

/// Top-level configuration persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Saved VPN profiles
    #[serde(default)]
    pub profiles: Vec<VpnProfile>,
    /// Application settings
    #[serde(default)]
    pub settings: AppSettings,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            settings: AppSettings::default(),
        }
    }
}

impl AppConfig {
    /// Path to the config directory: ~/.config/open-forti-manager/
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("open-forti-manager")
    }

    /// Path to the config file: ~/.config/open-forti-manager/config.json
    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.json")
    }

    /// Load configuration from disk, or return defaults if not found.
    pub fn load() -> Self {
        let path = Self::config_path();
        log::info!("Loading config from {:?}", path);
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => match serde_json::from_str::<AppConfig>(&contents) {
                    Ok(config) => {
                        log::info!("Loaded {} profile(s)", config.profiles.len());
                        return config;
                    }
                    Err(e) => {
                        log::error!("Failed to parse config: {}", e);
                    }
                },
                Err(e) => {
                    log::error!("Failed to read config: {}", e);
                }
            }
        }
        log::info!("No config found, using defaults");
        Self::default()
    }

    /// Save configuration to disk.
    pub fn save(&self) -> std::io::Result<()> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(Self::config_path(), json)?;
        log::info!("Config saved");
        Ok(())
    }

    /// Find a profile by name.
    #[allow(dead_code)]
    pub fn find_profile(&self, name: &str) -> Option<&VpnProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Find a profile by name (mutable).
    #[allow(dead_code)]
    pub fn find_profile_mut(&mut self, name: &str) -> Option<&mut VpnProfile> {
        self.profiles.iter_mut().find(|p| p.name == name)
    }
}
