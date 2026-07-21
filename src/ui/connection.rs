//! Connection tab — profile picker + live log output.

use gtk4::prelude::*;

/// Widgets owned by the Connection tab.
pub struct ConnectionPage {
    pub profile_combo: gtk4::DropDown,
    pub log_view: gtk4::TextView,
}

impl ConnectionPage {
    pub fn build(parent: &gtk4::Box) -> Self {
        use crate::ui::helpers::set_margin;

        let page = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
        set_margin(&page, 16);
        parent.append(&page);

        // Profile picker
        let profile_combo = {
            let model = gtk4::StringList::new(&[] as &[&str]);
            gtk4::DropDown::new(Some(model), None::<&gtk4::Expression>)
        };
        {
            let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
            row.append(&gtk4::Label::new(Some("Profile:")));
            row.append(&profile_combo);
            page.append(&row);
        }

        // Log output
        let log_view = gtk4::TextView::new();
        log_view.set_editable(false);
        log_view.set_monospace(true);
        log_view.set_cursor_visible(false);
        let log_scroll = gtk4::ScrolledWindow::new();
        log_scroll.set_child(Some(&log_view));
        log_scroll.set_vexpand(true);
        log_scroll.set_min_content_height(200);
        page.append(&log_scroll);

        Self { profile_combo, log_view }
    }

    /// Update the profile dropdown model.
    pub fn set_profiles(&self, names: &[&str]) {
        let model = gtk4::StringList::new(names);
        self.profile_combo.set_model(Some(&model));
    }

    /// Append log lines and auto-scroll.
    pub fn append_log(&self, lines: &[String]) -> Option<String> {
        let buf = self.log_view.buffer();
        let mut end = buf.end_iter();
        let mut saml_url: Option<String> = None;

        for line in lines {
            buf.insert(&mut end, &format!("{}\n", line));
            if line.contains("Authenticate at") {
                saml_url = line.split('\'').nth(1).map(|s| s.to_string());
            }
        }

        let mark = buf.create_mark(Some("end"), &buf.end_iter(), false);
        self.log_view.scroll_to_mark(&mark, 0.0, false, 0.0, 0.0);
        buf.delete_mark(&mark);

        saml_url
    }
}
