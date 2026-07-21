//! Profiles tab — profile list sidebar + editor form.

use crate::config::VpnProfile;
use crate::ui::helpers::{entry_row, opt, tri_get, tri_row, tri_set};
use gtk4::prelude::*;

/// Widgets owned by the Profiles tab.
pub struct ProfilesPage {
    pub list: gtk4::ListBox,
    pub name: gtk4::Entry,
    pub host: gtk4::Entry,
    pub port: gtk4::Entry,
    pub username: gtk4::Entry,
    pub password: gtk4::Entry,
    pub realm: gtk4::Entry,
    pub trusted_cert: gtk4::Entry,
    pub saml_login: gtk4::CheckButton,
    pub saml_port: gtk4::Entry,
    pub set_dns: gtk4::DropDown,
    pub set_routes: gtk4::DropDown,
    pub half_internet: gtk4::DropDown,
    pub save_btn: gtk4::Button,
    pub new_btn: gtk4::Button,
    pub del_btn: gtk4::Button,
}

impl ProfilesPage {
    /// Build the entire Profiles tab page and return the widget + state.
    pub fn build(parent: &gtk4::Box) -> Self {
        use crate::ui::helpers::set_margin;

        let prof_page = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        set_margin(&prof_page, 16);
        parent.append(&prof_page);

        // Left sidebar
        let list = gtk4::ListBox::new();
        list.set_size_request(260, -1);
        list.add_css_class("rich-list");
        list.set_selection_mode(gtk4::SelectionMode::Single);
        let list_scroll = gtk4::ScrolledWindow::new();
        list_scroll.set_child(Some(&list));
        list_scroll.set_vexpand(true);

        let new_btn = gtk4::Button::with_label("New Profile");
        let del_btn = gtk4::Button::with_label("Delete");
        let btn_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
        btn_box.set_margin_top(4);
        btn_box.set_homogeneous(true);
        btn_box.append(&new_btn);
        btn_box.append(&del_btn);

        let sidebar = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
        sidebar.set_hexpand(false);
        sidebar.set_halign(gtk4::Align::Start);
        sidebar.append(&list_scroll);
        sidebar.append(&btn_box);
        prof_page.append(&sidebar);

        // Editor form
        let editor = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
        editor.set_hexpand(true);
        prof_page.append(&editor);

        let name = entry_row(&editor, "Name:");
        let host = entry_row(&editor, "Host:");
        let port = entry_row(&editor, "Port:");
        let username = entry_row(&editor, "Username:");
        let password = entry_row(&editor, "Password:");
        password.set_visibility(false);
        let realm = entry_row(&editor, "Realm:");
        let trusted_cert = entry_row(&editor, "Trusted Cert (SHA256):");
        let saml_login = gtk4::CheckButton::with_label("Use SAML login");
        editor.append(&saml_login);
        let saml_port = entry_row(&editor, "SAML Port (default 8020):");

        // SAML toggle disables username/password
        {
            let u = username.clone();
            let p = password.clone();
            saml_login.connect_toggled(move |cb| {
                let active = cb.is_active();
                u.set_sensitive(!active);
                p.set_sensitive(!active);
            });
        }

        let set_dns = tri_row(&editor, "Set DNS:");
        let set_routes = tri_row(&editor, "Set Routes:");
        let half_internet = tri_row(&editor, "Half-Internet:");

        let save_btn = gtk4::Button::with_label("Save Profile");
        editor.append(&save_btn);

        // SAML toggle disables username/password
        let u = username.clone();
        let p = password.clone();
        saml_login.connect_toggled(move |cb| {
            let active = cb.is_active();
            u.set_sensitive(!active);
            p.set_sensitive(!active);
        });

        Self {
            list,
            name,
            host,
            port,
            username,
            password,
            realm,
            trusted_cert,
            saml_login,
            saml_port,
            set_dns,
            set_routes,
            half_internet,
            save_btn,
            new_btn,
            del_btn,
        }
    }

    /// Clear and repopulate the profile list from config.
    pub fn refresh_list(&self, profiles: &[VpnProfile]) {
        while let Some(row) = self.list.first_child() {
            self.list.remove(&row);
        }
        for p in profiles {
            let lbl = gtk4::Label::new(Some(&p.name));
            lbl.set_xalign(0.0);
            lbl.set_margin_start(8);
            lbl.set_margin_end(8);
            lbl.set_margin_top(4);
            lbl.set_margin_bottom(4);
            self.list.append(&lbl);
        }
    }

    /// Load a profile into the editor form.
    pub fn load(&self, p: &VpnProfile) {
        self.name.set_text(&p.name);
        self.host.set_text(&p.host);
        self.port.set_text(&p.port.map_or(String::new(), |v| v.to_string()));
        self.username.set_text(&p.username);
        self.password.set_text(p.password.as_deref().unwrap_or(""));
        self.realm.set_text(p.realm.as_deref().unwrap_or(""));
        self.trusted_cert.set_text(p.trusted_cert.as_deref().unwrap_or(""));
        let saml = p.saml_login.unwrap_or(false);
        self.saml_login.set_active(saml);
        self.saml_port.set_text(&p.saml_port.map_or(String::new(), |v| v.to_string()));
        self.username.set_sensitive(!saml);
        self.password.set_sensitive(!saml);
        tri_set(&self.set_dns, p.set_dns);
        tri_set(&self.set_routes, p.set_routes);
        tri_set(&self.half_internet, p.half_internet_routes);
    }

    /// Save form fields into a profile (mutates in-place).
    pub fn save_into(&self, p: &mut VpnProfile) {
        p.name = self.name.text().to_string();
        p.host = self.host.text().to_string();
        p.port = self.port.text().parse().ok();
        p.username = self.username.text().to_string();
        let pwd = self.password.text().to_string();
        p.password = if pwd.is_empty() { None } else { Some(pwd) };
        p.realm = opt(&self.realm.text());
        p.trusted_cert = opt(&self.trusted_cert.text());
        p.saml_login = Some(self.saml_login.is_active());
        p.saml_port = self.saml_port.text().parse().ok();
        p.set_dns = tri_get(&self.set_dns);
        p.set_routes = tri_get(&self.set_routes);
        p.half_internet_routes = tri_get(&self.half_internet);
    }
}
