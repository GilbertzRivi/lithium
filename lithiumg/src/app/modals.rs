use eframe::egui;

use super::{draw_invite_box, zero_str, Command, LithiumApp};

impl LithiumApp {
    pub(super) fn draw_wipe_modal(&mut self, ctx: &egui::Context) {
        if !self.wipe_modal_open {
            return;
        }

        let mut open = self.wipe_modal_open;

        egui::Window::new("Reset local data")
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 80, 80),
                    "This will erase all local daemon data.",
                );
                ui.add_space(4.0);
                ui.label(
                    "Keys, messages and contacts stored on this device will be permanently removed. \
                     The server account is not affected.",
                );
                ui.label(
                    egui::RichText::new(
                        "You will need to register again and re-add contacts afterwards.",
                    )
                    .weak()
                    .small(),
                );

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Reset local data"))
                        .clicked()
                    {
                        self.wipe_modal_open = false;
                        self.send(Command::WipeLocal);
                    }

                    if ui.button("Cancel").clicked() {
                        self.wipe_modal_open = false;
                    }
                });
            });

        self.wipe_modal_open = open;
    }

    pub(super) fn draw_register_capability_window(&mut self, ctx: &egui::Context) {
        if !self.show_register_capability_modal || self.register_capability.is_empty() {
            return;
        }

        let mut dismissed = false;

        egui::Window::new("Delete capability")
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 150, 50),
                    "Save this now — it will not be shown again.",
                );
                ui.add_space(4.0);
                ui.label(
                    "This is your delete capability. If you ever lose all your devices, \
                     it is the only way to request account removal from the server.",
                );
                ui.label(
                    egui::RichText::new(
                        "Treat it like a password — anyone who has it can request deletion.",
                    )
                    .weak()
                    .small(),
                );

                ui.add_space(8.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt("register_capability_scroll")
                        .max_height(96.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            let mut preview = self.register_capability.clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut preview)
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Copy to clipboard").clicked() {
                        ui.ctx().copy_text(self.register_capability.clone());
                        self.set_status("Delete capability copied to clipboard.");
                    }

                    if ui
                        .add(egui::Button::new(
                            egui::RichText::new("I saved it").strong(),
                        ))
                        .clicked()
                    {
                        dismissed = true;
                    }
                });
            });

        if dismissed {
            self.show_register_capability_modal = false;
            zero_str(&mut self.register_capability);
        }
    }

    pub(super) fn draw_remote_delete_window(&mut self, ctx: &egui::Context) {
        if !self.remote_delete_modal_open {
            return;
        }

        let mut open = self.remote_delete_modal_open;

        egui::Window::new("Emergency account removal")
            .collapsible(false)
            .resizable(true)
            .default_width(600.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(
                    "Use this when you have lost access to your device and need to remove \
                     the account from the server without being logged in.",
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "The server always responds with success — it does not confirm whether \
                         the capability was correct. Use 'Reset local data' separately if \
                         you also need to clear local files.",
                    )
                    .weak()
                    .small(),
                );

                if !self.register_capability.is_empty() {
                    ui.add_space(6.0);
                    if ui.button("Use capability from this session").clicked() {
                        self.remote_delete_capability_input = self.register_capability.clone();
                    }
                }

                ui.add_space(8.0);
                draw_invite_box(
                    ui,
                    "remote_delete_capability_input_scroll",
                    &mut self.remote_delete_capability_input,
                    "Paste delete capability",
                    true,
                );

                let can_submit =
                    !self.busy && !self.remote_delete_capability_input.trim().is_empty();

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let label = if self.confirm_remote_delete {
                        "Confirm removal"
                    } else {
                        "Request account removal"
                    };

                    if ui.add_enabled(can_submit, egui::Button::new(label)).clicked() {
                        if self.confirm_remote_delete {
                            let capability =
                                self.remote_delete_capability_input.trim().to_string();
                            self.confirm_remote_delete = false;
                            zero_str(&mut self.remote_delete_capability_input);
                            self.send(Command::RemoteDelete { capability });
                        } else {
                            self.confirm_remote_delete = true;
                            self.set_status(
                                "Click 'Confirm removal' to send the account removal request.",
                            );
                        }
                    }

                    if self.confirm_remote_delete && ui.button("Cancel").clicked() {
                        self.confirm_remote_delete = false;
                        self.set_status("Removal cancelled.");
                    }
                });
            });

        self.remote_delete_modal_open = open;
    }

    pub(super) fn draw_delete_account_window(&mut self, ctx: &egui::Context) {
        if !self.delete_account_modal_open {
            return;
        }

        let mut open = self.delete_account_modal_open;

        egui::Window::new("Delete account")
            .collapsible(false)
            .resizable(false)
            .default_width(480.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(
                    "This deletes the currently logged-in account from the server and resets \
                     the local profile to an unregistered state.",
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Use this when you are logged in and want to fully remove your account. \
                         Without a device, use 'Emergency account removal' instead.",
                    )
                    .weak()
                    .small(),
                );

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let label = if self.confirm_delete_account {
                        "Confirm deletion"
                    } else {
                        "Delete account"
                    };

                    if ui.add_enabled(!self.busy, egui::Button::new(label)).clicked() {
                        if self.confirm_delete_account {
                            self.confirm_delete_account = false;
                            self.send(Command::DeleteAccount);
                        } else {
                            self.confirm_delete_account = true;
                            self.set_status(
                                "Click 'Confirm deletion' to permanently delete your account.",
                            );
                        }
                    }

                    if self.confirm_delete_account && ui.button("Cancel").clicked() {
                        self.confirm_delete_account = false;
                        self.set_status("Deletion cancelled.");
                    }
                });
            });

        self.delete_account_modal_open = open;
    }
}