//! Certificates tab — CA bundle, user cert/key, trusted digest.

use gtk4::prelude::*;

/// Widgets owned by the Certificates tab.
pub struct CertsPage {
    pub ca_file: gtk4::Entry,
    pub user_cert: gtk4::Entry,
    pub user_key: gtk4::Entry,
    pub trusted_cert: gtk4::Entry,
    pub save_btn: gtk4::Button,
}

impl CertsPage {
    pub fn build(parent: &gtk4::Box) -> Self {
        use crate::ui::helpers::{entry_row, file_row, set_margin};

        let page = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
        set_margin(&page, 16);
        parent.append(&page);

        page.append(&gtk4::Label::new(Some("Certificate Files (per profile):")));
        let ca_file = file_row(&page, "CA Bundle:");
        let user_cert = file_row(&page, "User Cert:");
        let user_key = file_row(&page, "User Key:");
        page.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
        page.append(&gtk4::Label::new(Some("Trusted Certificate Digest (SHA256):")));
        let trusted_cert = entry_row(&page, "Digest:");
        let save_btn = gtk4::Button::with_label("Save Certificate Settings");
        page.append(&save_btn);

        Self { ca_file, user_cert, user_key, trusted_cert, save_btn }
    }
}
