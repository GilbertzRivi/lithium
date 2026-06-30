// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use eframe::egui;

use super::{Command, LithiumApp, zero_str};

impl LithiumApp {
    pub(super) fn draw_set_server_url(&mut self, ui: &mut egui::Ui) {
        let w = (380.0_f32).min(ui.available_width() - 40.0);

        ui.add_space(32.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(w);
            ui.heading("Server URL");
            ui.add_space(8.0);
            ui.label("Enter the URL of your Lithium server.");
            ui.add_space(16.0);

            let response = ui.add_sized(
                [w, 22.0],
                egui::TextEdit::singleline(&mut self.server_url_input)
                    .hint_text("https://your-server.example.com"),
            );

            let can_save = !self.busy && !self.server_url_input.trim().is_empty();
            let pressed_enter =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            ui.add_space(8.0);
            if ui
                .add_enabled(can_save, egui::Button::new("Save"))
                .clicked()
                || (can_save && pressed_enter)
            {
                let url = self.server_url_input.trim().to_string();
                self.send(Command::SetServerUrl { url });
            }
        });
    }

    pub(super) fn draw_set_server_identity(&mut self, ui: &mut egui::Ui) {
        let w = (380.0_f32).min(ui.available_width() - 40.0);

        ui.add_space(32.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(w);
            ui.heading("Server identity");
            ui.add_space(8.0);
            ui.label("The server.identity file was not found.");
            ui.label("Upload it to connect to your Lithium server.");
            ui.add_space(16.0);

            if let Some(path) = &self.server_identity_path {
                ui.label(format!("Selected: {}", path.display()));
                ui.add_space(8.0);
            }

            if ui.button("Browse...").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("Server identity", &["identity"])
                    .pick_file()
            {
                self.server_identity_path = Some(path);
            }

            ui.add_space(8.0);

            let can_upload = self.server_identity_path.is_some() && !self.busy;
            if ui
                .add_enabled(can_upload, egui::Button::new("Upload"))
                .clicked()
                && let Some(path) = &self.server_identity_path
            {
                match std::fs::read(path) {
                    Ok(data) => self.send(Command::SetServerIdentity { data }),
                    Err(e) => self.set_error(format!("Could not read file: {e}")),
                }
            }
        });
    }

    pub(super) fn draw_set_data_password(&mut self, ui: &mut egui::Ui) {
        let first_run = self
            .last_ping
            .as_ref()
            .map(|p| p.status.first_run)
            .unwrap_or(false);

        let w = (300.0_f32).min(ui.available_width() - 40.0);

        ui.add_space(32.0);
        ui.vertical_centered(|ui| {
            ui.heading(if first_run {
                "Welcome to Lithium"
            } else {
                "Set data password"
            });
            ui.add_space(8.0);
            if first_run {
                ui.label("Set a data password to protect your local keys.");
                ui.label("You will need it every time you start the app.");
            } else {
                ui.label("No local keystore found. Set a new data password to start fresh.");
            }

            ui.add_space(16.0);

            ui.add_sized(
                [w, 22.0],
                egui::TextEdit::singleline(&mut self.data_password)
                    .password(true)
                    .hint_text("Data password"),
            );
            ui.add_space(4.0);
            ui.add_sized(
                [w, 22.0],
                egui::TextEdit::singleline(&mut self.data_password_confirm)
                    .password(true)
                    .hint_text("Repeat data password"),
            );

            if !self.data_password_confirm.is_empty()
                && self.data_password != self.data_password_confirm
            {
                ui.add_space(4.0);
                ui.colored_label(
                    egui::Color32::from_rgb(220, 80, 80),
                    "Passwords do not match.",
                );
            }

            let can_submit = !self.busy
                && !self.data_password.is_empty()
                && self.data_password == self.data_password_confirm;

            ui.add_space(8.0);
            if ui
                .add_enabled(can_submit, egui::Button::new("Set password"))
                .clicked()
            {
                let pw = self.data_password.clone();
                zero_str(&mut self.data_password);
                zero_str(&mut self.data_password_confirm);
                self.send(Command::UnlockKeystore { data_password: pw });
            }
        });
    }

    pub(super) fn draw_unlock_data_password(&mut self, ui: &mut egui::Ui) {
        let w = (300.0_f32).min(ui.available_width() - 40.0);

        ui.add_space(32.0);
        ui.vertical_centered(|ui| {
            ui.heading("Enter data password");
            ui.add_space(8.0);
            ui.label("Enter your data password to unlock the local keystore.");
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Forgot it? There is no other way to authenticate you, if you own this machine you can delete the local files yourself and start over.")
                    .weak()
                    .small(),
            );

            ui.add_space(16.0);

            let response = ui.add_sized(
                [w, 22.0],
                egui::TextEdit::singleline(&mut self.data_password)
                    .password(true)
                    .hint_text("Data password"),
            );

            let can_submit = !self.busy && !self.data_password.is_empty();
            let pressed_enter =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            ui.add_space(8.0);
            if ui.add_enabled(can_submit, egui::Button::new("Unlock")).clicked()
                || (can_submit && pressed_enter)
            {
                let pw = self.data_password.clone();
                zero_str(&mut self.data_password);
                self.send(Command::UnlockKeystore { data_password: pw });
            }
        });
    }

    pub(super) fn draw_credentials(&mut self, ui: &mut egui::Ui) {
        let w = (300.0_f32).min(ui.available_width() - 40.0);

        ui.add_space(32.0);
        ui.vertical_centered(|ui| {
            ui.heading("Account credentials");
            ui.add_space(8.0);
            ui.label("Enter the username and password for your Lithium account.");

            ui.add_space(16.0);

            ui.add_sized(
                [w, 22.0],
                egui::TextEdit::singleline(&mut self.username).hint_text("Username"),
            );
            ui.add_space(4.0);

            let response = ui.add_sized(
                [w, 22.0],
                egui::TextEdit::singleline(&mut self.account_password)
                    .password(true)
                    .hint_text("Password"),
            );

            let can_submit =
                !self.busy && !self.username.trim().is_empty() && !self.account_password.is_empty();

            let pressed_enter =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            ui.add_space(8.0);
            if ui
                .add_enabled(can_submit, egui::Button::new("Save credentials"))
                .clicked()
                || (can_submit && pressed_enter)
            {
                let username = self.username.trim().to_string();
                let password = self.account_password.clone();
                zero_str(&mut self.account_password);
                zero_str(&mut self.account_password_confirm);
                self.send(Command::SetCredentials { username, password });
            }
        });
    }

    pub(super) fn draw_register(&mut self, ui: &mut egui::Ui) {
        let w = (420.0_f32).min(ui.available_width() - 40.0);

        ui.add_space(32.0);
        ui.vertical_centered(|ui| {
            ui.heading("Register account");
            ui.add_space(8.0);
            ui.label("Your profile is ready, but needs to be registered with the server.");

            ui.add_space(12.0);
            ui.allocate_ui_with_layout(
                egui::vec2(w, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 150, 50),
                            "Save your delete capability after registering.",
                        );
                        ui.add_space(4.0);
                        ui.label(
                            "Registration produces a one-time delete capability. \
                             It is the only way to request account removal if you \
                             lose access to your device. Treat it like a password.",
                        );
                    });
                },
            );

            ui.add_space(12.0);
            if ui
                .add_enabled(!self.busy, egui::Button::new("Register"))
                .clicked()
            {
                self.send(Command::Register);
            }
        });
    }

    pub(super) fn draw_unlock_storage(&mut self, ui: &mut egui::Ui) {
        ui.add_space(32.0);
        ui.vertical_centered(|ui| {
            ui.heading("Unlocking storage");
            ui.add_space(8.0);
            ui.label("Initializing local storage - this only takes a moment.");
            ui.add_space(12.0);
            if ui
                .add_enabled(!self.busy, egui::Button::new("Unlock storage"))
                .clicked()
            {
                self.send(Command::UnlockStorage);
            }
        });
    }
}
