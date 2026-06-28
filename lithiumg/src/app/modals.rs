// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use eframe::egui;

use super::{Command, LithiumApp, PairingStep, draw_invite_box, zero_str};

impl LithiumApp {
    pub(super) fn draw_pairing_modal(&mut self, ctx: &egui::Context) {
        if !self.pairing_modal_open {
            return;
        }

        let mut open = self.pairing_modal_open;

        egui::Window::new("Add contact")
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .open(&mut open)
            .show(ctx, |ui| {
                match self.pairing_step {
                    PairingStep::ChooseRole => {
                        ui.label("How are you adding this contact?");
                        ui.add_space(8.0);
                        if ui
                            .add_enabled(!self.busy, egui::Button::new("I'm inviting someone"))
                            .clicked()
                        {
                            self.pairing_error = None;
                            self.send(Command::CreateInvite { contact_id: None });
                        }
                        ui.add_space(4.0);
                        if ui
                            .add_enabled(!self.busy, egui::Button::new("I received an invitation"))
                            .clicked()
                        {
                            self.pairing_error = None;
                            self.pairing_step = PairingStep::ResponderCommitment;
                        }
                    }

                    PairingStep::InitiatorCommitment => {
                        ui.label("Step 1 — send this commitment to your contact:");
                        ui.add_space(4.0);
                        draw_invite_box(
                            ui,
                            "pairing_commitment_out",
                            &mut self.pairing_artifact,
                            "",
                            false,
                        );

                        ui.add_space(8.0);
                        ui.label("Step 2 — paste the code they send back:");
                        ui.add_space(4.0);
                        ui.add_sized(
                            [ui.available_width(), 24.0],
                            egui::TextEdit::singleline(&mut self.pairing_name_input)
                                .hint_text("Contact name"),
                        );
                        ui.add_space(4.0);
                        draw_invite_box(
                            ui,
                            "pairing_peer_in_initiator",
                            &mut self.pairing_peer_input,
                            "Paste their code",
                            true,
                        );

                        let can = !self.busy
                            && !self.pairing_name_input.trim().is_empty()
                            && !self.pairing_peer_input.trim().is_empty();
                        ui.add_space(8.0);
                        if ui
                            .add_enabled(can, egui::Button::new("Reveal my code"))
                            .clicked()
                            && let Some(cid) = self.pairing_contact_id.clone()
                        {
                            self.pairing_error = None;
                            self.send(Command::RevealInvite {
                                contact_id: cid,
                                peer_code: self.pairing_peer_input.trim().to_string(),
                                label: self.pairing_name_input.trim().to_string(),
                            });
                        }
                    }

                    PairingStep::InitiatorReveal => {
                        ui.label(
                            "Send this code to your contact. Pairing completes on their side.",
                        );
                        ui.add_space(4.0);
                        draw_invite_box(
                            ui,
                            "pairing_reveal_out",
                            &mut self.pairing_artifact,
                            "",
                            false,
                        );
                        ui.add_space(8.0);
                        if ui.button("Done").clicked() {
                            let cid = self.pairing_contact_id.clone();
                            self.clear_pairing_modal();
                            if let Some(cid) = cid {
                                self.pending_select_contact_id = Some(cid.clone());
                                self.pending_verify_contact_id = Some(cid);
                            }
                            self.send(Command::LoadContacts);
                        }
                    }

                    PairingStep::ResponderCommitment => {
                        ui.label("Paste the commitment your contact sent, and name them:");
                        ui.add_space(4.0);
                        ui.add_sized(
                            [ui.available_width(), 24.0],
                            egui::TextEdit::singleline(&mut self.pairing_name_input)
                                .hint_text("Contact name"),
                        );
                        ui.add_space(4.0);
                        draw_invite_box(
                            ui,
                            "pairing_commitment_in",
                            &mut self.pairing_peer_input,
                            "Paste commitment",
                            true,
                        );

                        let can = !self.busy
                            && !self.pairing_name_input.trim().is_empty()
                            && !self.pairing_peer_input.trim().is_empty();
                        ui.add_space(8.0);
                        if ui.add_enabled(can, egui::Button::new("Continue")).clicked() {
                            self.pairing_error = None;
                            self.send(Command::AcceptCommitment {
                                commitment: self.pairing_peer_input.trim().to_string(),
                                label: self.pairing_name_input.trim().to_string(),
                            });
                        }
                    }

                    PairingStep::ResponderCode => {
                        ui.label("Step 1 — send this code back to your contact:");
                        ui.add_space(4.0);
                        draw_invite_box(
                            ui,
                            "pairing_code_out",
                            &mut self.pairing_artifact,
                            "",
                            false,
                        );

                        ui.add_space(8.0);
                        ui.label("Step 2 — paste their final code to finish:");
                        ui.add_space(4.0);
                        draw_invite_box(
                            ui,
                            "pairing_peer_in_responder",
                            &mut self.pairing_peer_input,
                            "Paste their final code",
                            true,
                        );

                        let can = !self.busy && !self.pairing_peer_input.trim().is_empty();
                        ui.add_space(8.0);
                        if ui
                            .add_enabled(can, egui::Button::new("Finish pairing"))
                            .clicked()
                            && let Some(cid) = self.pairing_contact_id.clone()
                        {
                            self.pairing_error = None;
                            self.send(Command::FinalizePairing {
                                contact_id: cid,
                                peer_code: self.pairing_peer_input.trim().to_string(),
                            });
                        }
                    }
                }

                if let Some(err) = &self.pairing_error {
                    ui.add_space(8.0);
                    ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
                }
            });

        if !open {
            self.clear_pairing_modal();
        }
    }

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

                    if ui
                        .add_enabled(can_submit, egui::Button::new(label))
                        .clicked()
                    {
                        if self.confirm_remote_delete {
                            let capability = self.remote_delete_capability_input.trim().to_string();
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
                ui.label("This deletes the account from the server and wipes all local data.");
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Local keys, messages and contacts are erased. Without a device, \
                         use 'Emergency account removal' instead.",
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

                    if ui
                        .add_enabled(!self.busy, egui::Button::new(label))
                        .clicked()
                    {
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
