//! Settings tab — minimize-to-tray, minimize-after-connect, start-minimized.

use crate::config::AppSettings;
use gtk4::prelude::*;

/// Widgets owned by the Settings tab.
pub struct SettingsPage {
    pub minimize_to_tray: gtk4::CheckButton,
    pub minimize_after_connect: gtk4::CheckButton,
    pub start_minimized: gtk4::CheckButton,
    pub save_btn: gtk4::Button,
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

        let save_btn = gtk4::Button::with_label("Save Settings");
        page.append(&save_btn);

        page.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
        let cfg_path = crate::config::AppConfig::config_path();
        page.append(&gtk4::Label::new(Some(&format!(
            "Config: {}",
            cfg_path.display()
        ))));

        Self { minimize_to_tray, minimize_after_connect, start_minimized, save_btn }
    }

    /// Load settings values into the checkboxes.
    pub fn load(&self, s: &AppSettings) {
        self.minimize_to_tray.set_active(s.minimize_to_tray);
        self.minimize_after_connect.set_active(s.minimize_after_connect);
        self.start_minimized.set_active(s.start_minimized);
    }

    /// Read current checkbox values back into an AppSettings struct.
    pub fn apply_to(&self, s: &mut AppSettings) {
        s.minimize_to_tray = self.minimize_to_tray.is_active();
        s.minimize_after_connect = self.minimize_after_connect.is_active();
        s.start_minimized = self.start_minimized.is_active();
    }
}
