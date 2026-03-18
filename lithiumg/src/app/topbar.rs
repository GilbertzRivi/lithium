use eframe::egui;

use crate::ipc;

use super::{Command, LithiumApp};

impl LithiumApp {
    pub(super) fn draw_top_bar(&mut self, ui: &mut egui::Ui) {
        let has_ipc_auth = ipc::has_auth_token();

        // Button row — always the same height, never pushed by status text.
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() && !self.busy {
                self.send(Command::Ping);
            }

            if has_ipc_auth {
                ui.separator();
                if ui.add_enabled(!self.busy, egui::Button::new("Lock")).clicked() {
                    self.send(Command::LockKeystore);
                }
            }

            if !self.register_capability.is_empty() {
                ui.separator();
                if ui.button("Show delete capability").clicked() {
                    self.show_register_capability_modal = true;
                }
            }

            ui.separator();

            ui.menu_button("Server", |ui| {
                if ui.button("Change server URL...").clicked() {
                    self.screen = super::Screen::SetServerUrl;
                    ui.close();
                }
            });

            ui.separator();

            ui.menu_button("Account", |ui| {
                if ui
                    .add_enabled(has_ipc_auth && !self.busy, egui::Button::new("Delete account"))
                    .clicked()
                {
                    self.delete_account_modal_open = true;
                    self.confirm_delete_account = false;
                    ui.close();
                }

                ui.separator();

                if ui
                    .add_enabled(!self.busy, egui::Button::new("Emergency account removal..."))
                    .clicked()
                {
                    self.open_remote_delete_modal();
                    ui.close();
                }

                ui.separator();

                if ui
                    .add_enabled(has_ipc_auth && !self.busy, egui::Button::new("Reset local data..."))
                    .clicked()
                {
                    self.wipe_modal_open = true;
                    ui.close();
                }
            });

            if self.busy {
                ui.separator();
                ui.spinner();
            }
        });

        ui.separator();

        // Status line — separate row so its height never affects the button row above.
        ui.horizontal(|ui| {
            let text = egui::RichText::new(&self.status).small();
            let text = if self.status_is_error {
                text.color(egui::Color32::from_rgb(220, 80, 80))
            } else {
                text
            };
            ui.label(text);
        });

        if self.mk_rotation_error {
            ui.separator();
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(80, 30, 0))
                .inner_margin(egui::Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 160, 40),
                        "Master key rotation failed",
                    );
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(
                        "The keystore could not be re-encrypted. Possible causes: disk full, \
                         keystore directory missing or not writable, or corrupted key files.\n\
                         \n\
                         To fix: check that the keystore directory exists and is writable. \
                         If the error persists, use Account \u{2192} Reset local data to \
                         reinitialize (you will need to re-register)."
                    ).small());
                });
        }
    }
}