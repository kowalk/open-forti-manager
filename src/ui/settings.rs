//! Settings tab — minimize-to-tray, minimize-after-connect, start-minimized.

use crate::config::AppSettings;
use gtk4::prelude::*;

/// Widgets owned by the Settings tab.
pub struct SettingsPage {
    pub minimize_to_tray: gtk4::CheckButton,
    pub minimize_after_connect: gtk4::CheckButton,
    pub start_minimized: gtk4::CheckButton,
    /// Auto-connect-on-startup profile selector. Index 0 is "(None)".
    pub auto_connect: gtk4::DropDown,
    pub save_btn: gtk4::Button,
    /// Profile names currently in the auto-connect dropdown (index 0 = None).
    auto_names: std::cell::RefCell<Vec<String>>,
}

impl SettingsPage {
    pub fn build(parent: &gtk4::Box) -> Self {
        use crate::ui::helpers::set_margin;

        let page = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
        set_margin(&page, 16);
        parent.append(&page);

        let minimize_to_tray =
            gtk4::CheckButton::with_label("Minimize to tray on close");
        let minimize_after_connect =
            gtk4::CheckButton::with_label("Minimize window after connecting");
        let start_minimized =
            gtk4::CheckButton::with_label("Start minimized");

        page.append(&minimize_to_tray);
        page.append(&minimize_after_connect);
        page.append(&start_minimized);

        // Auto-connect on startup: "(None)" + profile names (populated later).
        let auto_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        auto_row.append(&gtk4::Label::new(Some("Auto-connect on startup:")));
        let auto_connect = {
            let model = gtk4::StringList::new(&["(None)"]);
            gtk4::DropDown::new(Some(model), None::<&gtk4::Expression>)
        };
        auto_row.append(&auto_connect);
        page.append(&auto_row);

        let save_btn = gtk4::Button::with_label("Save Settings");
        page.append(&save_btn);

        page.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
        let cfg_path = crate::config::AppConfig::config_path();
        page.append(&gtk4::Label::new(Some(&format!(
            "Config: {}",
            cfg_path.display()
        ))));

        Self {
            minimize_to_tray,
            minimize_after_connect,
            start_minimized,
            auto_connect,
            save_btn,
            auto_names: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Populate the auto-connect dropdown with the available profile names.
    /// Index 0 is always "(None)".
    pub fn set_profiles(&self, names: &[&str]) {
        let mut items = vec!["(None)"];
        items.extend_from_slice(names);
        let model = gtk4::StringList::new(&items);
        self.auto_connect.set_model(Some(&model));
        *self.auto_names.borrow_mut() = names.iter().map(|s| s.to_string()).collect();
    }

    /// Load settings values into the widgets.
    pub fn load(&self, s: &AppSettings) {
        self.minimize_to_tray.set_active(s.minimize_to_tray);
        self.minimize_after_connect.set_active(s.minimize_after_connect);
        self.start_minimized.set_active(s.start_minimized);

        // Select the configured auto-connect profile (0 = None).
        let idx = match &s.auto_connect_profile {
            Some(name) => self
                .auto_names
                .borrow()
                .iter()
                .position(|n| n == name)
                .map(|i| i as u32 + 1)
                .unwrap_or(0),
            None => 0,
        };
        self.auto_connect.set_selected(idx);
    }

    /// Read current widget values back into an AppSettings struct.
    pub fn apply_to(&self, s: &mut AppSettings) {
        s.minimize_to_tray = self.minimize_to_tray.is_active();
        s.minimize_after_connect = self.minimize_after_connect.is_active();
        s.start_minimized = self.start_minimized.is_active();

        let sel = self.auto_connect.selected();
        s.auto_connect_profile = if sel == 0 {
            None
        } else {
            self.auto_names.borrow().get(sel as usize - 1).cloned()
        };
    }
}
