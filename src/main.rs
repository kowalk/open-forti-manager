//! OpenForti Manager — native Fortinet SSL-VPN client with a GTK4 + libadwaita GUI.

mod app;
mod config;
mod tray;
mod ui;
mod vpn;
mod engine;

use crate::app::AppWindow;
use crate::config::AppConfig;
use crate::engine::backend::NativeVpnBackend;
use crate::tray::{spawn_tray, SharedState};
use crate::vpn::VpnBackend;
use gtk4::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    log::info!("OpenForti Manager starting up");

    let config = AppConfig::load();
    let start_minimized = config.settings.start_minimized;

    // --- Shared state ---
    let shared = Arc::new(RwLock::new(SharedState::new()));
    {
        let mut s = shared.write().unwrap();
        s.show_window = !start_minimized;
    }

    // --- Tokio runtime ---
    let rt = tokio::runtime::Runtime::new().expect("Tokio runtime");

    // --- System tray ---
    let tray_handle = rt.block_on(async {
        spawn_tray(shared.clone()).await.expect("Tray")
    });

    // --- GTK Application ---
    let app = gtk4::Application::new(
        Some("com.openforti.manager"),
        gtk4::gio::ApplicationFlags::default(),
    );

    // --- Native VPN backend ---
    let vpn_backend: Rc<RefCell<dyn VpnBackend>> =
        Rc::new(RefCell::new(NativeVpnBackend::new()));

    let shared_for_app = shared.clone();
    let config_for_app = config.clone();

    app.connect_activate(move |gtk_app| {
        log::info!("GTK activate — creating window");
        AppWindow::new(
            gtk_app,
            config_for_app.clone(),
            shared_for_app.clone(),
            tray_handle.clone(),
            rt.handle().clone(),
            vpn_backend.clone(),
        );
    });

    log::info!("Starting GTK main loop");

    // We need to run the GTK main loop, but we also have the tokio
    // runtime.  gtk4's run() will block, so we run it here.
    let empty_args: Vec<String> = Vec::new();
    app.run_with_args(&empty_args);

    log::info!("Shutting down");
}
