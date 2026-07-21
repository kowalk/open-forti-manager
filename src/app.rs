use crate::config::{AppConfig, VpnProfile};
use crate::tray::SharedState;
use crate::ui::certs::CertsPage;
use crate::ui::connection::ConnectionPage;
use crate::ui::helpers::opt;
use crate::ui::profiles::ProfilesPage;
use crate::ui::settings::SettingsPage;
use crate::vpn::{ConnectionState, VpnBackend, VpnManager};
use gtk4::prelude::*;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

pub struct AppWindow {
    window: libadwaita::ApplicationWindow,
    config: Rc<RefCell<AppConfig>>,
    shared: Arc<RwLock<SharedState>>,
    vpn: Rc<RefCell<VpnManager>>,
    tray_handle: ksni::Handle<crate::tray::AppTray>,
    rt: tokio::runtime::Handle,

    // UI pages
    connection: ConnectionPage,
    profiles: ProfilesPage,
    certs: CertsPage,
    settings: SettingsPage,

    // Header bar widgets
    status_dot: gtk4::DrawingArea,
    status_label: gtk4::Label,
    connect_btn: gtk4::Button,
    was_connected: bool,
}

impl AppWindow {
    pub fn new(
        app: &gtk4::Application,
        config: AppConfig,
        shared: Arc<RwLock<SharedState>>,
        tray_handle: ksni::Handle<crate::tray::AppTray>,
        rt: tokio::runtime::Handle,
    ) -> Rc<RefCell<Self>> {
        let config = Rc::new(RefCell::new(config));
        let vpn = Rc::new(RefCell::new(VpnManager::new()));

        // --- Window ---
        let window = libadwaita::ApplicationWindow::new(app);
        window.set_title(Some("OpenForti Manager"));
        window.set_default_size(800, 600);

        // --- Header bar ---
        let header = libadwaita::HeaderBar::new();

        let status_dot = gtk4::DrawingArea::new();
        status_dot.set_content_width(14);
        status_dot.set_content_height(14);
        status_dot.set_valign(gtk4::Align::Center);
        status_dot.set_margin_end(6);
        status_dot.set_draw_func(|_, cr, _w, _h| {
            cr.set_source_rgb(0.6, 0.6, 0.6);
            cr.arc(7.0, 7.0, 5.0, 0.0, std::f64::consts::TAU);
            let _ = cr.fill();
        });
        header.pack_start(&status_dot);

        let status_label = gtk4::Label::new(Some("Disconnected"));
        status_label.set_valign(gtk4::Align::Center);
        header.pack_start(&status_label);

        let connect_btn = gtk4::Button::with_label("Connect");
        connect_btn.add_css_class("suggested-action");
        header.pack_end(&connect_btn);

        let title_widget = libadwaita::WindowTitle::new("OpenForti Manager", "");
        header.set_title_widget(Some(&title_widget));

        // --- Tab view ---
        let view_stack = libadwaita::TabView::new();
        let tab_bar = libadwaita::TabBar::new();
        tab_bar.set_view(Some(&view_stack));

        // Build tab pages via submodules
        let conn_page = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        let connection = ConnectionPage::build(&conn_page);
        let conn_tab = view_stack.add_page(&conn_page, None);
        conn_tab.set_title("Connection");

        let prof_wrapper = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        let profiles = ProfilesPage::build(&prof_wrapper);
        let prof_tab = view_stack.add_page(&prof_wrapper, None);
        prof_tab.set_title("Profiles");

        let cert_wrapper = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        let certs = CertsPage::build(&cert_wrapper);
        let cert_tab = view_stack.add_page(&cert_wrapper, None);
        cert_tab.set_title("Certificates");

        let set_wrapper = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        let settings = SettingsPage::build(&set_wrapper);
        let set_tab = view_stack.add_page(&set_wrapper, None);
        set_tab.set_title("Settings");

        // --- Layout ---
        let main_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        main_box.append(&header);
        main_box.append(&tab_bar);
        main_box.append(&view_stack);
        window.set_content(Some(&main_box));

        // Clone before struct moves them
        let connect_btn_clone = connect_btn.clone();

        // --- Create struct ---
        let slf = Rc::new(RefCell::new(Self {
            window: window.clone(),
            config: config.clone(),
            shared: shared.clone(),
            vpn: vpn.clone(),
            tray_handle: tray_handle.clone(),
            rt: rt.clone(),
            connection,
            profiles,
            certs,
            settings,
            status_dot,
            status_label,
            connect_btn,
            was_connected: false,
        }));

        // Detect existing VPN connection
        if VpnManager::is_running_global() {
            vpn.borrow_mut().set_state(ConnectionState::Connected);
            log::info!("Detected existing VPN connection");
        }

        // Load initial data
        slf.borrow_mut().refresh_profile_list();
        {
            let cfg = config.borrow();
            slf.borrow().settings.load(&cfg.settings);
        }
        {
            let s = slf.borrow();
            if let Some(first_row) = s.profiles.list.row_at_index(0) {
                s.profiles.list.select_row(Some(&first_row));
            }
        }
        slf.borrow_mut().on_profile_selected(0);

        // --- Signals ---
        {
            let s = slf.clone();
            connect_btn_clone.connect_clicked(move |_| s.borrow_mut().toggle_connection());
        }
        {
            let s = slf.clone();
            let new_btn = slf.borrow().profiles.new_btn.clone();
            new_btn.connect_clicked(move |_| s.borrow_mut().new_profile());
        }
        {
            let s = slf.clone();
            let del_btn = slf.borrow().profiles.del_btn.clone();
            del_btn.connect_clicked(move |_| s.borrow_mut().delete_profile());
        }
        {
            let s = slf.clone();
            slf.borrow().profiles.save_btn.connect_clicked(move |_| s.borrow_mut().save_profile());
        }
        {
            let s = slf.clone();
            let cert_save = slf.borrow().certs.save_btn.clone();
            cert_save.connect_clicked(move |_| s.borrow_mut().save_profile());
        }
        {
            let s = slf.clone();
            let list = slf.borrow().profiles.list.clone();
            list.connect_row_activated(move |_, row| {
                s.borrow_mut().on_profile_selected(row.index() as usize);
            });
        }
        {
            let s = slf.clone();
            let list = slf.borrow().profiles.list.clone();
            list.connect_row_selected(move |_, row| {
                if let Some(r) = row {
                    s.borrow_mut().on_profile_selected(r.index() as usize);
                }
            });
        }
        {
            let s = slf.clone();
            slf.borrow().settings.save_btn.connect_clicked(move |_| s.borrow_mut().save_settings());
        }
        // Close → minimize to tray, or show keep-connection dialog
        {
            let w = window.clone();
            let s = slf.clone();
            window.connect_close_request(move |_win| {
                let force = { s.borrow().shared.read().unwrap().force_quit };
                if force {
                    if let Ok(mut state) = s.borrow().shared.write() {
                        state.force_quit = false;
                    }
                    return gtk4::glib::Propagation::Proceed;
                }

                let this = s.borrow();
                if this.config.borrow().settings.minimize_to_tray {
                    if let Ok(mut state) = this.shared.write() {
                        state.show_window = false;
                    }
                    drop(this);
                    w.set_visible(false);
                    gtk4::glib::Propagation::Stop
                } else if this.vpn.borrow().state().is_active() {
                    drop(this);
                    s.borrow().show_quit_dialog();
                    gtk4::glib::Propagation::Stop
                } else {
                    gtk4::glib::Propagation::Proceed
                }
            });
        }
        // Periodic poll
        {
            let s = slf.clone();
            gtk4::glib::timeout_add_local(std::time::Duration::from_millis(250), move || {
                s.borrow_mut().poll();
                gtk4::glib::ControlFlow::Continue
            });
        }

        window.present();
        slf
    }

    // ------------------------------------------------------------------
    // Periodic state poll
    // ------------------------------------------------------------------

    fn poll(&mut self) {
        self.vpn.borrow_mut().check_status();
        let new_lines = self.vpn.borrow_mut().drain_log();

        // Handle tray Quick Connect / Disconnect requests
        {
            let mut s = self.shared.write().unwrap();
            if s.disconnect_requested {
                s.disconnect_requested = false;
                drop(s);
                if self.vpn.borrow().state().is_active() {
                    let _ = self.vpn.borrow_mut().disconnect();
                }
            } else if s.quick_connect_requested {
                s.quick_connect_requested = false;
                if let Some(ref profile_name) = s.last_connected_profile.clone() {
                    if let Some(profile) = self.config.borrow().find_profile(profile_name).cloned() {
                        drop(s);
                        if !self.vpn.borrow().state().is_active() {
                            let _ = self.vpn.borrow_mut().connect(&profile);
                        }
                    }
                }
            }
        }

        // Minimize-after-connect
        {
            let state = self.vpn.borrow().state().clone();
            let is_connected = matches!(state, ConnectionState::Connected);
            if is_connected && !self.was_connected {
                if let Some(name) = self.selected_profile().map(|p| p.name) {
                    self.shared.write().unwrap().last_connected_profile = Some(name);
                }
                if self.config.borrow().settings.minimize_after_connect {
                    if let Ok(mut s) = self.shared.write() {
                        s.show_window = false;
                    }
                    self.window.set_visible(false);
                }
            }
            self.was_connected = is_connected;
        }

        // Append log lines, detect SAML URLs
        if !new_lines.is_empty() {
            if let Some(url) = self.connection.append_log(&new_lines) {
                log::info!("Opening SAML URL: {}", url);
                let _ = std::process::Command::new("xdg-open")
                    .arg(&url)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
            }
        }

        // Sync shared state + tray
        {
            let state = self.vpn.borrow().state().clone();
            self.shared.write().unwrap().connection_state = state;
        }
        let h = self.tray_handle.clone();
        let _ = self.rt.block_on(async { h.update(|_| {}).await });

        // Tray show request
        if self.shared.read().unwrap().show_window {
            self.window.present();
        }

        // Tray Quit request — show dialog on GTK thread (only once)
        {
            let mut s = self.shared.write().unwrap();
            if s.quit_requested {
                s.quit_requested = false;
                drop(s);
                self.show_quit_dialog();
            }
        }

        self.update_status_ui();
    }

    /// Ask the user whether to keep or disconnect the VPN before quitting.
    fn show_quit_dialog(&self) {
        if !self.vpn.borrow().state().is_active() {
            self.window.close();
            return;
        }

        // Custom response IDs
        const RESP_KEEP: gtk4::ResponseType = gtk4::ResponseType::Other(1);
        const RESP_DISCONNECT: gtk4::ResponseType = gtk4::ResponseType::Other(2);

        let dialog = gtk4::MessageDialog::new(
            Some(&self.window),
            gtk4::DialogFlags::MODAL,
            gtk4::MessageType::Question,
            gtk4::ButtonsType::None,
            "Keep VPN connection?",
        );
        dialog.set_secondary_text(Some(
            "You are currently connected. Keep the connection running after closing, or disconnect now?",
        ));
        dialog.add_button("Cancel", gtk4::ResponseType::Cancel);
        dialog.add_button("Disconnect and Quit", RESP_DISCONNECT);
        dialog.add_button("Keep Connected", RESP_KEEP);
        dialog.set_default_response(gtk4::ResponseType::Cancel);

        let shared = self.shared.clone();
        let vpn = self.vpn.clone();
        let window = self.window.clone();

        dialog.connect_response(move |dlg, response| {
            match response {
                RESP_KEEP => {
                    if let Ok(mut s) = shared.write() {
                        s.force_quit = true;
                    }
                    dlg.close();
                    window.close();
                }
                RESP_DISCONNECT => {
                    // Use synchronous disconnect so the pkexec password
                    // dialog completes before we exit the app
                    let _ = vpn.borrow_mut().disconnect_sync();
                    if let Ok(mut s) = shared.write() {
                        s.force_quit = true;
                    }
                    dlg.close();
                    window.close();
                }
                _ => {
                    dlg.close();
                }
            }
        });

        dialog.present();
    }

    fn update_status_ui(&self) {
        let state = self.vpn.borrow().state().clone();
        let (r, g, b, label) = match state {
            ConnectionState::Disconnected => (0.6, 0.6, 0.6, "Disconnected"),
            ConnectionState::Connecting => (1.0, 0.76, 0.03, "Connecting\u{2026}"),
            ConnectionState::Connected => (0.3, 0.69, 0.31, "Connected"),
            ConnectionState::Disconnecting => (1.0, 0.6, 0.0, "Disconnecting\u{2026}"),
            ConnectionState::Error(_) => (0.96, 0.26, 0.21, "Error"),
        };

        self.status_dot.set_draw_func(move |_, cr, _w, _h| {
            cr.set_source_rgb(r, g, b);
            cr.arc(7.0, 7.0, 5.0, 0.0, std::f64::consts::TAU);
            let _ = cr.fill();
        });
        self.status_dot.queue_draw();
        self.status_label.set_label(label);

        let is_active = state.is_active();
        if is_active {
            self.connect_btn.set_label("Disconnect");
            self.connect_btn.remove_css_class("suggested-action");
            self.connect_btn.add_css_class("destructive-action");
        } else {
            self.connect_btn.set_label("Connect");
            self.connect_btn.remove_css_class("destructive-action");
            self.connect_btn.add_css_class("suggested-action");
        }
    }

    fn toggle_connection(&mut self) {
        if self.vpn.borrow().state().is_active() {
            let _ = self.vpn.borrow_mut().disconnect();
        } else if let Some(p) = self.selected_profile() {
            let _ = self.vpn.borrow_mut().connect(&p);
        }
        self.update_status_ui();
    }

    // ------------------------------------------------------------------
    // Profile CRUD (delegates to ProfilesPage)
    // ------------------------------------------------------------------

    fn refresh_profile_list(&mut self) {
        let cfg = self.config.borrow();
        self.profiles.refresh_list(&cfg.profiles);
        let names: Vec<&str> = cfg.profiles.iter().map(|p| p.name.as_str()).collect();
        self.connection.set_profiles(&names);
    }

    fn on_profile_selected(&mut self, idx: usize) {
        if let Some(p) = self.config.borrow().profiles.get(idx).cloned() {
            self.profiles.load(&p);
            self.certs.ca_file.set_text(p.ca_file.as_deref().unwrap_or(""));
            self.certs.user_cert.set_text(p.user_cert.as_deref().unwrap_or(""));
            self.certs.user_key.set_text(p.user_key.as_deref().unwrap_or(""));
            self.certs.trusted_cert.set_text(p.trusted_cert.as_deref().unwrap_or(""));
        }
    }

    fn selected_profile(&self) -> Option<VpnProfile> {
        let idx = self.connection.profile_combo.selected() as usize;
        self.config.borrow().profiles.get(idx).cloned()
    }

    fn new_profile(&mut self) {
        let name = format!("Profile {}", self.config.borrow().profiles.len() + 1);
        self.config.borrow_mut().profiles.push(VpnProfile::new(&name, "", ""));
        let _ = self.config.borrow().save();
        self.refresh_profile_list();
    }

    fn delete_profile(&mut self) {
        let idx = self.profiles.list.selected_row().map(|r| r.index() as usize).unwrap_or(0);
        if idx < self.config.borrow().profiles.len() {
            self.config.borrow_mut().profiles.remove(idx);
            let _ = self.config.borrow().save();
            self.refresh_profile_list();
        }
    }

    fn save_profile(&mut self) {
        let idx = self.profiles.list.selected_row().map(|r| r.index() as usize).unwrap_or(0);
        {
            let mut cfg = self.config.borrow_mut();
            if let Some(p) = cfg.profiles.get_mut(idx) {
                self.profiles.save_into(p);
                // Cert fields from certs tab
                p.ca_file = opt(&self.certs.ca_file.text());
                p.user_cert = opt(&self.certs.user_cert.text());
                p.user_key = opt(&self.certs.user_key.text());
                // trusted_cert: profiles tab wins, certs tab as fallback
                let tc = self.profiles.trusted_cert.text();
                let tc2 = self.certs.trusted_cert.text();
                p.trusted_cert = if !tc.is_empty() { opt(&tc) } else { opt(&tc2) };
            }
            let _ = cfg.save();
        }
        self.refresh_profile_list();
    }

    fn save_settings(&mut self) {
        {
            let mut cfg = self.config.borrow_mut();
            self.settings.apply_to(&mut cfg.settings);
            let _ = cfg.save();
        }
        log::info!("Settings saved");
    }
}
