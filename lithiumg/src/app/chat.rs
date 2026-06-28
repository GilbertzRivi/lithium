// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use eframe::egui;

use super::{Command, LithiumApp};

impl LithiumApp {
    pub(super) fn draw_ready(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let narrow = ui.available_width() < 760.0;

        if narrow {
            ui.vertical(|ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    self.draw_contacts_panel(ui, true);
                });
                ui.add_space(8.0);
                self.draw_messages_panel(ui);
            });
        } else {
            egui::SidePanel::left("contacts_panel")
                .resizable(true)
                .default_width(300.0)
                .min_width(220.0)
                .max_width(480.0)
                .show_inside(ui, |ui| {
                    self.draw_contacts_panel(ui, false);
                });

            egui::CentralPanel::default().show_inside(ui, |ui| {
                self.draw_messages_panel(ui);
            });
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn draw_contacts_panel(&mut self, ui: &mut egui::Ui, compact: bool) {
        ui.heading("Contacts");

        ui.horizontal_wrapped(|ui| {
            if ui.button("Refresh").clicked() && !self.busy {
                self.send(Command::LoadContacts);
            }

            if ui.button("Add contact").clicked() && !self.busy {
                self.open_pairing_modal();
            }
        });

        ui.separator();

        let mut clicked_contact_id: Option<String> = None;

        let mut scroll = egui::ScrollArea::vertical().auto_shrink([false, false]);
        if compact {
            scroll = scroll.max_height(180.0);
        }

        scroll.show(ui, |ui| {
            for contact in &self.contacts {
                let is_selected =
                    self.selected_contact_id.as_deref() == Some(contact.contact_id.as_str());

                let name = if contact.label.is_empty() {
                    &contact.contact_id
                } else {
                    &contact.label
                };

                let label = if contact.peer_set {
                    name.clone()
                } else {
                    format!("{name} (pending)")
                };

                if ui
                    .add_sized(
                        [ui.available_width(), 24.0],
                        egui::Button::selectable(is_selected, label),
                    )
                    .clicked()
                {
                    clicked_contact_id = Some(contact.contact_id.clone());
                }
            }
        });

        if let Some(contact_id) = clicked_contact_id {
            self.selected_contact_id = Some(contact_id.clone());
            self.send(Command::LoadMessages { contact_id });
        }
    }

    fn draw_messages_panel(&mut self, ui: &mut egui::Ui) {
        let selected = self.selected_contact().cloned();

        let Some(contact) = selected else {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(egui::RichText::new("Select a contact to start messaging.").weak());
            });
            return;
        };

        let show_verify_here = self.verify_modal_open
            && self.verify_modal_contact_id.as_deref() == Some(contact.contact_id.as_str())
            && !self.verify_modal_emojis.is_empty();

        ui.horizontal(|ui| {
            let name = if contact.label.is_empty() {
                contact.contact_id.clone()
            } else {
                contact.label.clone()
            };
            ui.heading(name);

            if !contact.peer_set {
                ui.separator();
                ui.label(
                    egui::RichText::new("Pending — awaiting contact reply")
                        .weak()
                        .italics(),
                );
            }
        });

        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy, egui::Button::new("Refresh"))
                .clicked()
            {
                self.send(Command::LoadMessages {
                    contact_id: contact.contact_id.clone(),
                });
            }

            if ui
                .add_enabled(!self.busy, egui::Button::new("Remove contact"))
                .clicked()
            {
                self.send(Command::ForgetContact {
                    contact_id: contact.contact_id.clone(),
                });
            }
        });

        ui.separator();

        let compose_height = if show_verify_here { 230.0 } else { 120.0 };
        let list_height = (ui.available_height() - compose_height).max(80.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(list_height)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if self.messages.is_empty() {
                    if show_verify_here {
                        self.draw_verify_card(ui);
                        ui.add_space(10.0);
                    }
                    ui.vertical_centered(|ui| {
                        ui.add_space(16.0);
                        ui.label(egui::RichText::new("No messages yet.").weak());
                    });
                } else {
                    for msg in &self.messages {
                        let is_mine = msg.direction == "out";
                        let sender = if is_mine { "You" } else { &contact.label };
                        let text = msg
                            .text
                            .clone()
                            .unwrap_or_else(|| "(unsupported message type)".into());

                        // Show time only — drop internal message ID.
                        let time = msg
                            .created_at
                            .split('T')
                            .nth(1)
                            .and_then(|t| t.get(..5))
                            .unwrap_or(&msg.created_at);

                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("{sender}  ·  {time}"))
                                        .small()
                                        .weak(),
                                );
                            });
                            ui.label(&text);
                        });
                        ui.add_space(4.0);
                    }

                    if show_verify_here {
                        self.draw_verify_card(ui);
                        ui.add_space(8.0);
                    }
                }
            });

        ui.separator();

        let compose_response = ui.add(
            egui::TextEdit::multiline(&mut self.message_text)
                .desired_rows(3)
                .desired_width(f32::INFINITY)
                .hint_text("Write a message…"),
        );

        let can_send = !self.busy && contact.peer_set && !self.message_text.trim().is_empty();

        let send_shortcut = compose_response.has_focus()
            && ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::Enter));

        if ui
            .add_enabled(can_send, egui::Button::new("Send"))
            .clicked()
            || (can_send && send_shortcut)
        {
            let text = self.message_text.trim().to_string();
            self.message_text.clear();
            self.send(Command::SendMessage {
                contact_id: contact.contact_id.clone(),
                plaintext: text,
            });
        }

        if !contact.peer_set {
            ui.label(
                egui::RichText::new(
                    "Messaging will be available once the contact accepts your invite.",
                )
                .small()
                .weak(),
            );
        }
    }

    pub(super) fn draw_verify_card(&mut self, ui: &mut egui::Ui) {
        let emoji_line = self.verify_modal_emojis.join("   ");

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("Safety verification").strong());
                ui.add_space(4.0);
                ui.label(
                    "Compare these codes with your contact over a trusted channel \
                     (phone call, in person, etc.).",
                );
                ui.add_space(8.0);
                ui.label(egui::RichText::new(emoji_line).size(28.0).strong());
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("If they don't match, remove the contact and start over.")
                        .small()
                        .weak(),
                );
                ui.add_space(8.0);
                if ui.button("Dismiss").clicked() {
                    self.clear_verify_modal();
                }
            });
        });
    }
}
