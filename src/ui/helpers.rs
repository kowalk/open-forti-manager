//! Shared GTK4 widget helpers used across tab pages.

use gtk4::prelude::*;

/// Set all four margins on a widget.
pub fn set_margin(w: &impl IsA<gtk4::Widget>, m: i32) {
    w.set_margin_top(m);
    w.set_margin_bottom(m);
    w.set_margin_start(m);
    w.set_margin_end(m);
}

/// Create a tri-state dropdown (Default / Yes / No).
pub fn tri_dd() -> gtk4::DropDown {
    let model = gtk4::StringList::new(&["Default", "Yes", "No"]);
    gtk4::DropDown::new(Some(model), None::<&gtk4::Expression>)
}

pub fn tri_get(dd: &gtk4::DropDown) -> Option<bool> {
    match dd.selected() {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

pub fn tri_set(dd: &gtk4::DropDown, v: Option<bool>) {
    dd.set_selected(match v {
        Some(true) => 1,
        Some(false) => 2,
        None => 0,
    });
}

/// Label + Entry row. Returns the Entry.
pub fn entry_row(parent: &gtk4::Box, label: &str) -> gtk4::Entry {
    let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    row.append(&gtk4::Label::new(Some(label)));
    let entry = gtk4::Entry::new();
    entry.set_hexpand(true);
    row.append(&entry);
    parent.append(&row);
    entry
}

/// Label + Entry + Browse button. Returns the Entry.
pub fn file_row(parent: &gtk4::Box, label: &str) -> gtk4::Entry {
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

/// Label + tri-state dropdown row. Returns the DropDown.
pub fn tri_row(parent: &gtk4::Box, label: &str) -> gtk4::DropDown {
    let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    row.append(&gtk4::Label::new(Some(label)));
    let dd = tri_dd();
    row.append(&dd);
    parent.append(&row);
    dd
}

/// Convert empty string to None.
pub fn opt(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_string()) }
}
