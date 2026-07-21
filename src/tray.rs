use crate::vpn::ConnectionState;
use ksni::menu::{MenuItem, StandardItem};
use ksni::{Icon, Tray, TrayMethods};
use std::sync::{Arc, RwLock};

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

pub struct SharedState {
    pub connection_state: ConnectionState,
    pub connected_profile: Option<String>,
    pub show_window: bool,
    /// Edge-triggered request to bring the window to the front (consumed by poll).
    pub raise_requested: bool,
    pub quit_requested: bool,
    pub force_quit: bool,
    pub quick_connect_requested: bool,
    pub disconnect_requested: bool,
    pub last_connected_profile: Option<String>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            connection_state: ConnectionState::Disconnected,
            connected_profile: None,
            show_window: true,
            raise_requested: false,
            quit_requested: false,
            force_quit: false,
            quick_connect_requested: false,
            disconnect_requested: false,
            last_connected_profile: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Icon helpers — generate ARGB32 pixel data for ksni::Icon
// ---------------------------------------------------------------------------

/// Build a circular status icon as ARGB32 raw pixels.
fn make_icon_pixels(r: u8, g: u8, b: u8, size: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity((size * size * 4) as usize);
    let center = size as f32 / 2.0;
    let radius = size as f32 / 2.0 - 1.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();

            let (a, cr, cg, cb) = if dist <= radius {
                let alpha = if dist >= radius - 1.0 {
                    ((radius - dist) * 255.0) as u8
                } else {
                    255
                };
                (alpha, r, g, b)
            } else {
                (0u8, 0u8, 0u8, 0u8)
            };

            // ARGB32 network byte order (same as big-endian [A,R,G,B])
            data.push(a);
            data.push(cr);
            data.push(cg);
            data.push(cb);
        }
    }
    data
}

// ---------------------------------------------------------------------------
// ksni Tray implementation
// ---------------------------------------------------------------------------

pub struct AppTray {
    state: Arc<RwLock<SharedState>>,
    /// Pre-rendered ARGB32 pixel data for each connection state.
    icon_disconnected: Vec<u8>,
    icon_connecting: Vec<u8>,
    icon_connected: Vec<u8>,
    icon_disconnecting: Vec<u8>,
    icon_error: Vec<u8>,
    /// Icon dimensions (square).
    icon_size: u32,
}

impl AppTray {
    pub fn new(state: Arc<RwLock<SharedState>>) -> Self {
        let size: u32 = 64;
        Self {
            state,
            icon_disconnected: make_icon_pixels(158, 158, 158, size),
            icon_connecting: make_icon_pixels(255, 193, 7, size),
            icon_connected: make_icon_pixels(76, 175, 80, size),
            icon_disconnecting: make_icon_pixels(255, 152, 0, size),
            icon_error: make_icon_pixels(244, 67, 54, size),
            icon_size: size,
        }
    }

    fn current_icon_data(&self) -> Vec<u8> {
        let s = self.state.read().unwrap();
        match s.connection_state {
            ConnectionState::Disconnected => self.icon_disconnected.clone(),
            ConnectionState::Connecting => self.icon_connecting.clone(),
            ConnectionState::Connected => self.icon_connected.clone(),
            ConnectionState::Disconnecting => self.icon_disconnecting.clone(),
            ConnectionState::Error(_) => self.icon_error.clone(),
        }
    }

    fn current_tooltip(&self) -> String {
        let s = self.state.read().unwrap();
        let status = s.connection_state.label();
        match &s.connected_profile {
            Some(p) => format!("OpenForti Manager — {} ({})", status, p),
            None => format!("OpenForti Manager — {}", status),
        }
    }
}

impl Tray for AppTray {
    fn id(&self) -> String {
        "open-forti-manager".into()
    }

    fn title(&self) -> String {
        "OpenForti Manager".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![Icon {
            width: self.icon_size as i32,
            height: self.icon_size as i32,
            data: self.current_icon_data(),
        }]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "OpenForti Manager".into(),
            description: self.current_tooltip(),
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let show_state = self.state.clone();
        vec![
            MenuItem::Standard(StandardItem {
                label: "Show Window".into(),
                enabled: true,
                visible: true,
                activate: Box::new(move |_tray: &mut Self| {
                    if let Ok(mut s) = show_state.write() {
                        s.show_window = true;
                        s.raise_requested = true; // bring to front even if already open
                    }
                }),
                ..Default::default()
            }),
            {
                let is_connected = self.state.read().unwrap().connection_state.is_active();
                let label = if is_connected { "Disconnect" } else { "Quick Connect" };
                let st = self.state.clone();
                MenuItem::Standard(StandardItem {
                    label: label.into(),
                    enabled: true,
                    visible: true,
                    activate: Box::new(move |_tray: &mut Self| {
                        let mut s = st.write().unwrap();
                        if s.connection_state.is_active() {
                            s.disconnect_requested = true;
                        } else {
                            s.quick_connect_requested = true;
                            s.show_window = false;
                        }
                    }),
                    ..Default::default()
                })
            },
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "Quit".into(),
                enabled: true,
                visible: true,
                activate: Box::new(|tray: &mut Self| {
                    // Signal the GTK thread to show exit confirmation
                    if let Ok(mut s) = tray.state.write() {
                        s.quit_requested = true;
                    }
                }),
                ..Default::default()
            }),
        ]
    }

    /// Left-click → toggle window visibility; when showing, raise to front.
    fn activate(&mut self, _x: i32, _y: i32) {
        if let Ok(mut s) = self.state.write() {
            s.show_window = !s.show_window;
            if s.show_window {
                s.raise_requested = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn helper — runs the tray asynchronously
// ---------------------------------------------------------------------------

/// Spawn the tray icon service and return a handle.
/// Must be called from within a tokio async context.
pub async fn spawn_tray(
    state: Arc<RwLock<SharedState>>,
) -> Result<ksni::Handle<AppTray>, ksni::Error> {
    let tray = AppTray::new(state);
    let handle = tray.spawn().await?;
    log::info!("System tray icon spawned");
    Ok(handle)
}
