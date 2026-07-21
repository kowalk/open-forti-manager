use crate::config::{AppConfig, VpnProfile};
use crate::tray::SharedState;
use crate::vpn::{ConnectionState, VpnManager};
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
    status_dot: gtk4::DrawingArea,
    status_label: gtk4::Label,
    connect_btn: gtk4::Button,
    log_view: gtk4::TextView,
    profile_list: gtk4::ListBox,
    edit_name: gtk4::Entry,
    edit_host: gtk4::Entry,
    edit_port: gtk4::Entry,
    edit_username: gtk4::Entry,
    edit_password: gtk4::Entry,
    edit_realm: gtk4::Entry,
    edit_ca_file: gtk4::Entry,
    edit_user_cert: gtk4::Entry,
    edit_user_key: gtk4::Entry,
    edit_trusted_cert: gtk4::Entry,
    edit_profile_trusted_cert: gtk4::Entry,
    edit_profile_saml_login: gtk4::CheckButton,
    edit_profile_saml_port: gtk4::Entry,
    edit_set_dns: gtk4::DropDown,
    edit_set_routes: gtk4::DropDown,
    edit_half_internet: gtk4::DropDown,
    conn_profile_combo: gtk4::DropDown,
    setting_minimize_to_tray: gtk4::CheckButton,
    setting_minimize_after_connect: gtk4::CheckButton,
    setting_start_minimized: gtk4::CheckButton,
    was_connected: bool,
}

fn set_margin(w: &impl IsA<gtk4::Widget>, m: i32) {
    w.set_margin_top(m);
    w.set_margin_bottom(m);
    w.set_margin_start(m);
    w.set_margin_end(m);
}

fn tri_dd() -> gtk4::DropDown {
    let model = gtk4::StringList::new(&["Default", "Yes", "No"]);
    gtk4::DropDown::new(Some(model), None::<&gtk4::Expression>)
}

fn tri_get(dd: &gtk4::DropDown) -> Option<bool> {
    match dd.selected() { 1 => Some(true), 2 => Some(false), _ => None }
}

fn tri_set(dd: &gtk4::DropDown, v: Option<bool>) {
    dd.set_selected(match v { Some(true) => 1, Some(false) => 2, None => 0 });
}

fn entry_row(parent: &gtk4::Box, label: &str) -> gtk4::Entry {
    let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    row.append(&gtk4::Label::new(Some(label)));
    let entry = gtk4::Entry::new();
    entry.set_hexpand(true);
    row.append(&entry);
    parent.append(&row);
    entry
}

fn file_row(parent: &gtk4::Box, label: &str) -> gtk4::Entry {
    let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    row.append(&gtk4::Label::new(Some(label)));
    let entry = gtk4::Entry::new();
    entry.set_hexpand(true);
    row.append(&entry);
    let btn = gtk4::Button::with_label("Browse\u{2026}");
    let e = entry.clone();
    btn.connect_clicked(move |_| {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            e.set_text(&path.display().to_string());
        }
    });
    row.append(&btn);
    parent.append(&row);
    entry
}

fn tri_row(parent: &gtk4::Box, label: &str) -> gtk4::DropDown {
    let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    row.append(&gtk4::Label::new(Some(label)));
    let dd = tri_dd();
    row.append(&dd);
    parent.append(&row);
    dd
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
            cr.fill().unwrap();
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

        // --- Tab bar + view stack ---
        let view_stack = libadwaita::TabView::new();
        let tab_bar = libadwaita::TabBar::new();
        tab_bar.set_view(Some(&view_stack));

        // Connection page
        let conn_page = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
        set_margin(&conn_page, 16);
        let conn_tab = view_stack.add_page(&conn_page, None);
        conn_tab.set_title("Connection");

        let profile_combo = {
            let model = gtk4::StringList::new(&[] as &[&str]);
            gtk4::DropDown::new(Some(model), None::<&gtk4::Expression>)
        };
        {
            let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
            row.append(&gtk4::Label::new(Some("Profile:")));
            row.append(&profile_combo);
            conn_page.append(&row);
        }

        let log_view = gtk4::TextView::new();
        log_view.set_editable(false);
        log_view.set_monospace(true);
        log_view.set_cursor_visible(false);
        let log_scroll = gtk4::ScrolledWindow::new();
        log_scroll.set_child(Some(&log_view));
        log_scroll.set_vexpand(true);
        log_scroll.set_min_content_height(200);
        conn_page.append(&log_scroll);

        // Profiles page
        let prof_page = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        set_margin(&prof_page, 16);
        let prof_tab = view_stack.add_page(&prof_page, None);
        prof_tab.set_title("Profiles");

        let profile_list = gtk4::ListBox::new();
        profile_list.set_size_request(260, -1);
        profile_list.add_css_class("rich-list");
        profile_list.set_selection_mode(gtk4::SelectionMode::Single);
        let list_scroll = gtk4::ScrolledWindow::new();
        list_scroll.set_child(Some(&profile_list));
        list_scroll.set_vexpand(true);

        let new_btn = gtk4::Button::with_label("New Profile");
        let del_btn = gtk4::Button::with_label("Delete");
        let btn_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
        btn_box.set_margin_top(4);
        btn_box.set_homogeneous(true);
        btn_box.append(&new_btn);
        btn_box.append(&del_btn);

        // Left sidebar: list + buttons
        let sidebar = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
        sidebar.set_hexpand(false);
        sidebar.set_halign(gtk4::Align::Start);
        sidebar.append(&list_scroll);
        sidebar.append(&btn_box);
        prof_page.append(&sidebar);

        let editor_box = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
        editor_box.set_hexpand(true);
        prof_page.append(&editor_box);

        let edit_name = entry_row(&editor_box, "Name:");
        let edit_host = entry_row(&editor_box, "Host:");
        let edit_port = entry_row(&editor_box, "Port:");
        let edit_username = entry_row(&editor_box, "Username:");
        let edit_password = entry_row(&editor_box, "Password:");
        edit_password.set_visibility(false);
        let edit_realm = entry_row(&editor_box, "Realm:");
        let edit_profile_trusted_cert = entry_row(&editor_box, "Trusted Cert (SHA256):");
        let edit_profile_saml_login = gtk4::CheckButton::with_label("Use SAML login");
        editor_box.append(&edit_profile_saml_login);
        let edit_profile_saml_port = entry_row(&editor_box, "SAML Port (default 8020):");

        // Clone now before these get moved into closures
        let saml_uname = edit_username.clone();
        let saml_passwd = edit_password.clone();
        let saml_cb = edit_profile_saml_login.clone();

        let edit_set_dns = tri_row(&editor_box, "Set DNS:");
        let edit_set_routes = tri_row(&editor_box, "Set Routes:");
        let edit_half_internet = tri_row(&editor_box, "Half-Internet:");

        let save_btn = gtk4::Button::with_label("Save Profile");
        editor_box.append(&save_btn);

        // Certificates page
        let cert_page = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
        set_margin(&cert_page, 16);
        let cert_tab = view_stack.add_page(&cert_page, None);
        cert_tab.set_title("Certificates");

        cert_page.append(&gtk4::Label::new(Some("Certificate Files (per profile):")));
        let edit_ca_file = file_row(&cert_page, "CA Bundle:");
        let edit_user_cert = file_row(&cert_page, "User Cert:");
        let edit_user_key = file_row(&cert_page, "User Key:");
        cert_page.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
        cert_page.append(&gtk4::Label::new(Some("Trusted Certificate Digest (SHA256):")));
        let edit_trusted_cert = entry_row(&cert_page, "Digest:");
        let cert_save_btn = gtk4::Button::with_label("Save Certificate Settings");
        cert_page.append(&cert_save_btn);

        // Settings page
        let set_page = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
        set_margin(&set_page, 16);
        let set_tab = view_stack.add_page(&set_page, None);
        set_tab.set_title("Settings");

        let setting_minimize_to_tray =
            gtk4::CheckButton::with_label("Minimize to tray on close");
        let setting_minimize_after_connect =
            gtk4::CheckButton::with_label("Minimize window after connecting");
        let setting_start_minimized =
            gtk4::CheckButton::with_label("Start minimized");

        set_page.append(&setting_minimize_to_tray);
        set_page.append(&setting_minimize_after_connect);
        set_page.append(&setting_start_minimized);

        let settings_save_btn = gtk4::Button::with_label("Save Settings");
        set_page.append(&settings_save_btn);

        set_page.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
        let cfg_path = AppConfig::config_path();
        set_page.append(&gtk4::Label::new(Some(&format!(
            "Config: {}",
            cfg_path.display()
        ))));

        // --- Layout ---
        let main_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        main_box.append(&header);
        main_box.append(&tab_bar);
        main_box.append(&view_stack);
        window.set_content(Some(&main_box));

        // --- Create struct ---
        let slf = Rc::new(RefCell::new(Self {
            window: window.clone(),
            config: config.clone(),
            shared: shared.clone(),
            vpn: vpn.clone(),
            tray_handle: tray_handle.clone(),
            rt: rt.clone(),
            status_dot: status_dot.clone(),
            status_label: status_label.clone(),
            connect_btn: connect_btn.clone(),
            log_view: log_view.clone(),
            profile_list: profile_list.clone(),
            edit_name,
            edit_host,
            edit_port,
            edit_username,
            edit_password,
            edit_realm,
            edit_ca_file,
            edit_user_cert,
            edit_user_key,
            edit_trusted_cert,
            edit_profile_trusted_cert,
            edit_profile_saml_login,
            edit_profile_saml_port,
            edit_set_dns,
            edit_set_routes,
            edit_half_internet,
            conn_profile_combo: profile_combo.clone(),
            setting_minimize_to_tray: setting_minimize_to_tray.clone(),
            setting_minimize_after_connect: setting_minimize_after_connect.clone(),
            setting_start_minimized: setting_start_minimized.clone(),
            was_connected: false,
        }));

        // Detect if a VPN connection is already running
        if VpnManager::is_running() {
            {
                let mut v = vpn.borrow_mut();
                v.set_state(ConnectionState::Connected);
            }
            log::info!("Detected existing VPN connection");
        }

        // Load initial data
        slf.borrow_mut().refresh_profile_list();
        {
            let cfg = config.borrow();
            setting_minimize_to_tray.set_active(cfg.settings.minimize_to_tray);
            setting_minimize_after_connect.set_active(cfg.settings.minimize_after_connect);
            setting_start_minimized.set_active(cfg.settings.start_minimized);
        }
        // Auto-select first profile
        if let Some(first_row) = profile_list.row_at_index(0) {
            profile_list.select_row(Some(&first_row));
            slf.borrow_mut().on_profile_selected(0);
        }

        // --- Signals ---

        // Connect / Disconnect
        {
            let s = slf.clone();
            connect_btn.connect_clicked(move |_| s.borrow_mut().toggle_connection());
        }

        // New / Delete profile
        {
            let s = slf.clone();
            new_btn.connect_clicked(move |_| s.borrow_mut().new_profile());
        }
        {
            let s = slf.clone();
            del_btn.connect_clicked(move |_| s.borrow_mut().delete_profile());
        }

        // Save profile
        {
            let s = slf.clone();
            save_btn.connect_clicked(move |_| s.borrow_mut().save_profile());
        }
        {
            let s = slf.clone();
            cert_save_btn.connect_clicked(move |_| s.borrow_mut().save_profile());
        }

        // SAML login toggles username/password
        saml_cb.connect_toggled(move |cb| {
            let active = cb.is_active();
            saml_uname.set_sensitive(!active);
            saml_passwd.set_sensitive(!active);
        });

        // Profile list selection
        {
            let s = slf.clone();
            profile_list.connect_row_activated(move |_, row| {
                s.borrow_mut().on_profile_selected(row.index() as usize);
            });
        }
        {
            let s = slf.clone();
            profile_list.connect_row_selected(move |_, row| {
                if let Some(r) = row {
                    s.borrow_mut().on_profile_selected(r.index() as usize);
                }
            });
        }

        // Save settings
        {
            let s = slf.clone();
            settings_save_btn.connect_clicked(move |_| s.borrow_mut().save_settings());
        }

        // Close → minimize to tray, or quit with VPN cleanup
        {
            let w = window.clone();
            let s = slf.clone();
            window.connect_close_request(move |_win| {
                let this = s.borrow();
                if this.config.borrow().settings.minimize_to_tray {
                    if let Ok(mut state) = this.shared.write() {
                        state.show_window = false;
                    }
                    w.set_visible(false);
                    gtk4::glib::Propagation::Stop
                } else {
                    let mut vpn = this.vpn.borrow_mut();
                    let _ = vpn.disconnect();
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

    fn poll(&mut self) {
        self.vpn.borrow_mut().check_status();
        let new_lines = self.vpn.borrow_mut().drain_log();

        // Handle tray "Quick Connect" / "Disconnect" requests
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

        // Handle minimize-after-connect
        {
            let state = self.vpn.borrow().state().clone();
            let is_connected = matches!(state, ConnectionState::Connected);
            if is_connected && !self.was_connected {
                // Just connected — store as last connected profile
                let profile_name = self.selected_profile()
                    .map(|p| p.name);
                if let Some(name) = profile_name {
                    let mut s = self.shared.write().unwrap();
                    s.last_connected_profile = Some(name);
                }
                // Minimize if setting is enabled
                if self.config.borrow().settings.minimize_after_connect {
                    if let Ok(mut s) = self.shared.write() {
                        s.show_window = false;
                    }
                    self.window.set_visible(false);
                }
            }
            self.was_connected = is_connected;
        }

        // Append new log lines to the log view
        if !new_lines.is_empty() {
            let buf = self.log_view.buffer();
            let mut end = buf.end_iter();
            for line in &new_lines {
                buf.insert(&mut end, &format!("{}\n", line));

                // Auto-open SAML login URLs in the browser
                if line.contains("Authenticate at") {
                    if let Some(url) = line.split('\'').nth(1) {
                        log::info!("Opening SAML URL: {}", url);
                        let _ = std::process::Command::new("xdg-open")
                            .arg(url)
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .spawn();
                    }
                }
            }
            // Auto-scroll to bottom
            let mark = buf.create_mark(Some("end"), &buf.end_iter(), false);
            self.log_view.scroll_to_mark(&mark, 0.0, false, 0.0, 0.0);
            buf.delete_mark(&mark);
        }

        {
            let state = self.vpn.borrow().state().clone();
            let mut s = self.shared.write().unwrap();
            s.connection_state = state;
        }

        // Update tray
        let h = self.tray_handle.clone();
        let _ = self.rt.block_on(async { h.update(|_| {}).await });

        // Check tray show request
        {
            let show = self.shared.read().unwrap().show_window;
            if show {
                self.window.present();
            }
        }

        self.update_status_ui();
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
            cr.fill().unwrap();
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

    fn refresh_profile_list(&mut self) {
        // Clear list
        while let Some(row) = self.profile_list.first_child() {
            self.profile_list.remove(&row);
        }

        let cfg = self.config.borrow();
        let names: Vec<String> = cfg.profiles.iter().map(|p| p.name.clone()).collect();

        for name in &names {
            let lbl = gtk4::Label::new(Some(name));
            lbl.set_xalign(0.0);
            lbl.set_margin_start(8);
            lbl.set_margin_end(8);
            lbl.set_margin_top(4);
            lbl.set_margin_bottom(4);
            self.profile_list.append(&lbl);
        }

        let names_ref: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let model = gtk4::StringList::new(&names_ref);
        self.conn_profile_combo.set_model(Some(&model));
    }

    fn on_profile_selected(&mut self, idx: usize) {
        if let Some(p) = self.config.borrow().profiles.get(idx) {
            self.edit_name.set_text(&p.name);
            self.edit_host.set_text(&p.host);
            self.edit_port.set_text(&p.port.map_or(String::new(), |v| v.to_string()));
            self.edit_username.set_text(&p.username);
            self.edit_password.set_text(p.password.as_deref().unwrap_or(""));
            self.edit_realm.set_text(p.realm.as_deref().unwrap_or(""));
            self.edit_ca_file.set_text(p.ca_file.as_deref().unwrap_or(""));
            self.edit_user_cert.set_text(p.user_cert.as_deref().unwrap_or(""));
            self.edit_user_key.set_text(p.user_key.as_deref().unwrap_or(""));
            self.edit_trusted_cert.set_text(p.trusted_cert.as_deref().unwrap_or(""));
            self.edit_profile_trusted_cert.set_text(p.trusted_cert.as_deref().unwrap_or(""));
            let saml = p.saml_login.unwrap_or(false);
            self.edit_profile_saml_login.set_active(saml);
            self.edit_profile_saml_port.set_text(&p.saml_port.map_or(String::new(), |v| v.to_string()));
            self.edit_username.set_sensitive(!saml);
            self.edit_password.set_sensitive(!saml);
            tri_set(&self.edit_set_dns, p.set_dns);
            tri_set(&self.edit_set_routes, p.set_routes);
            tri_set(&self.edit_half_internet, p.half_internet_routes);
        }
    }

    fn selected_profile(&self) -> Option<VpnProfile> {
        let idx = self.conn_profile_combo.selected() as usize;
        self.config.borrow().profiles.get(idx).cloned()
    }

    fn new_profile(&mut self) {
        let name = format!("Profile {}", self.config.borrow().profiles.len() + 1);
        self.config.borrow_mut().profiles.push(VpnProfile::new(&name, "", ""));
        let _ = self.config.borrow().save();
        self.refresh_profile_list();
    }

    fn delete_profile(&mut self) {
        if let Some(row) = self.profile_list.selected_row() {
            let idx = row.index() as usize;
            if idx < self.config.borrow().profiles.len() {
                self.config.borrow_mut().profiles.remove(idx);
                let _ = self.config.borrow().save();
                self.refresh_profile_list();
            }
        }
    }

    fn save_profile(&mut self) {
        let idx = self.profile_list
            .selected_row()
            .map(|r| r.index() as usize)
            .unwrap_or(0);

        {
            let mut cfg = self.config.borrow_mut();
            if let Some(p) = cfg.profiles.get_mut(idx) {
                p.name = self.edit_name.text().to_string();
                p.host = self.edit_host.text().to_string();
                p.port = self.edit_port.text().parse().ok();
                p.username = self.edit_username.text().to_string();
                let pwd = self.edit_password.text().to_string();
                p.password = if pwd.is_empty() { None } else { Some(pwd) };
                p.ca_file = opt(self.edit_ca_file.text().as_str());
                p.user_cert = opt(self.edit_user_cert.text().as_str());
                p.user_key = opt(self.edit_user_key.text().as_str());
                // Use the profile editor's trusted cert, falling back to certs tab
                let tc = self.edit_profile_trusted_cert.text();
                let tc2 = self.edit_trusted_cert.text();
                p.trusted_cert = if !tc.is_empty() { opt(tc.as_str()) } else { opt(tc2.as_str()) };
                p.saml_login = Some(self.edit_profile_saml_login.is_active());
                p.saml_port = self.edit_profile_saml_port.text().parse().ok();
                p.realm = opt(self.edit_realm.text().as_str());
                p.set_dns = tri_get(&self.edit_set_dns);
                p.set_routes = tri_get(&self.edit_set_routes);
                p.half_internet_routes = tri_get(&self.edit_half_internet);
            }
            let _ = cfg.save();
        }
        self.refresh_profile_list();
    }

    fn save_settings(&mut self) {
        {
            let mut cfg = self.config.borrow_mut();
            cfg.settings.minimize_to_tray = self.setting_minimize_to_tray.is_active();
            cfg.settings.minimize_after_connect = self.setting_minimize_after_connect.is_active();
            cfg.settings.start_minimized = self.setting_start_minimized.is_active();
            let _ = cfg.save();
        }
        log::info!("Settings saved");
    }
}

fn opt(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_string()) }
}
