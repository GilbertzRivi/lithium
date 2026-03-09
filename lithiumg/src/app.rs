use std::sync::mpsc::{Receiver, Sender};

use eframe::egui;

use crate::ipc::{
    self, AcceptInviteResult, ContactInfo, CreateInviteResult, MessageItem, MessagesResult, PingResult,
};

#[derive(Debug, Clone)]
pub enum Command {
    Ping,
    UnlockKeystore { data_password: String },
    SetCredentials { handler: String, password: String },
    Register,
    UnlockStorage,
    LoadContacts,
    LoadMessages { contact_id: String },
    SendMessage { contact_id: String, plaintext: String },
    FetchMessages { contact_id: String },
    CreateInvite { contact_id: Option<String> },
    AcceptInvite { code: String, label: String, contact_id: Option<String> },
    ForgetContact { contact_id: String },
    WipeLocal,
}

#[derive(Debug)]
pub enum WorkerEvent {
    Ping(Result<PingResult, String>),
    UnlockKeystore(Result<(), String>),
    SetCredentials(Result<(), String>),
    Register(Result<(), String>),
    UnlockStorage(Result<(), String>),
    Contacts(Result<Vec<ContactInfo>, String>),
    Messages {
        contact_id: String,
        result: Result<MessagesResult, String>,
        note: Option<String>,
    },
    CreateInvite(Result<CreateInviteResult, String>),
    AcceptInvite(Result<AcceptInviteResult, String>),
    ForgetContact {
        contact_id: String,
        result: Result<(), String>,
    },
    WipeLocal(Result<(), String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Connecting,
    DaemonOffline,
    SetDataPassword,
    UnlockDataPassword,
    Credentials,
    Register,
    UnlockStorage,
    Ready,
}

pub struct LithiumApp {
    tx: Sender<Command>,
    rx: Receiver<WorkerEvent>,

    screen: Screen,
    busy: bool,
    status_line: String,

    data_password: String,
    data_password_confirm: String,

    handler: String,
    account_password: String,

    contacts: Vec<ContactInfo>,
    selected_contact_id: Option<String>,
    messages: Vec<MessageItem>,
    message_text: String,

    invite_code_input: String,
    invite_label_input: String,
    generated_invite_code: String,

    pending_select_contact_id: Option<String>,

    account_password_confirm: String,
    confirm_wipe_local: bool,
}

impl LithiumApp {
    pub fn new(tx: Sender<Command>, rx: Receiver<WorkerEvent>) -> Self {
        let mut app = Self {
            tx,
            rx,
            screen: Screen::Connecting,
            busy: false,
            status_line: "Connecting to daemon...".into(),
            data_password: String::new(),
            data_password_confirm: String::new(),
            handler: String::new(),
            account_password: String::new(),
            contacts: Vec::new(),
            selected_contact_id: None,
            messages: Vec::new(),
            message_text: String::new(),
            invite_code_input: String::new(),
            invite_label_input: String::new(),
            generated_invite_code: String::new(),
            pending_select_contact_id: None,
            account_password_confirm: String::new(),
            confirm_wipe_local: false,
        };

        app.send(Command::Ping);
        app
    }

    fn send(&mut self, cmd: Command) {
        self.busy = true;
        let _ = self.tx.send(cmd);
    }

    fn selected_contact(&self) -> Option<&ContactInfo> {
        let id = self.selected_contact_id.as_ref()?;
        self.contacts.iter().find(|c| &c.contact_id == id)
    }

    fn set_status<S: Into<String>>(&mut self, s: S) {
        self.status_line = s.into();
    }

    fn drain_events(&mut self) {
        while let Ok(evt) = self.rx.try_recv() {
            self.busy = false;
            self.handle_event(evt);
        }
    }

    fn handle_ping(&mut self, ping: PingResult) {
        let s = &ping.status;
        let _ = (
            s.has_proto,
            s.has_keys,
            s.has_credentials,
            s.has_data_password,
            s.needs_register,
            s.has_dek,
            s.has_local_db,
            s.is_registered_on_disk,
            s.has_local_db_on_disk,
            s.first_run,
            ping.pong,
            ping.actions_needed.len(),
        );

        self.screen = match ping.ui_state.as_str() {
            "keystore_locked" => {
                if s.has_keystore_on_disk {
                    Screen::UnlockDataPassword
                } else {
                    Screen::SetDataPassword
                }
            }
            "needs_credentials" => Screen::Credentials,
            "needs_register" => Screen::Register,
            "storage_locked" => Screen::UnlockStorage,
            "ready" => Screen::Ready,
            _ => Screen::DaemonOffline,
        };

        self.set_status(match self.screen {
            Screen::Connecting => "Connecting...",
            Screen::DaemonOffline => "Daemon offline or not responding.",
            Screen::SetDataPassword => "First run: set your data password.",
            Screen::UnlockDataPassword => "Enter your data password.",
            Screen::Credentials => "Enter account credentials.",
            Screen::Register => "Account needs registration.",
            Screen::UnlockStorage => "Unlock local storage.",
            Screen::Ready => "Ready.",
        });

        if self.screen == Screen::Ready {
            self.send(Command::LoadContacts);
        }
    }

    fn handle_event(&mut self, evt: WorkerEvent) {
        match evt {
            WorkerEvent::Ping(res) => match res {
                Ok(ping) => self.handle_ping(ping),
                Err(e) => {
                    self.screen = Screen::DaemonOffline;
                    self.set_status(format!("Daemon unavailable: {e}"));
                }
            },

            WorkerEvent::UnlockKeystore(res) => match res {
                Ok(()) => {
                    self.data_password_confirm.clear();
                    self.confirm_wipe_local = false;
                    self.set_status("Keystore unlocked.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_status(format!("Unlock failed: {e}")),
            },

            WorkerEvent::SetCredentials(res) => match res {
                Ok(()) => {
                    self.account_password_confirm.clear();
                    self.confirm_wipe_local = false;
                    self.set_status("Credentials saved.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_status(format!("Saving credentials failed: {e}")),
            },

            WorkerEvent::Register(res) => match res {
                Ok(()) => {
                    self.confirm_wipe_local = false;
                    self.set_status("Registered.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_status(format!("Register failed: {e}")),
            },

            WorkerEvent::UnlockStorage(res) => match res {
                Ok(()) => {
                    self.confirm_wipe_local = false;
                    self.set_status("Storage unlocked.");
                    self.send(Command::Ping);
                }
                Err(e) => {
                    let e_lower = e.to_ascii_lowercase();

                    let should_reask_credentials =
                        e_lower.contains("invalid_credentials")
                            || e_lower.contains("bad_credentials")
                            || e_lower.contains("http_400")
                            || e_lower.contains("http_401")
                            || e_lower.contains("protocol_error");

                    if should_reask_credentials {
                        self.screen = Screen::Credentials;
                        self.account_password.clear();
                        self.account_password_confirm.clear();
                        self.confirm_wipe_local = false;
                        self.set_status(
                            "Unlock storage failed: invalid account credentials. Enter them again.",
                        );
                    } else {
                        self.set_status(format!("Unlock storage failed: {e}"));
                    }
                }
            },

            WorkerEvent::Contacts(res) => match res {
                Ok(contacts) => {
                    self.contacts = contacts;

                    if let Some(pending) = self.pending_select_contact_id.take() {
                        self.selected_contact_id = Some(pending);
                    } else if self.selected_contact_id.is_none() && !self.contacts.is_empty() {
                        self.selected_contact_id = Some(self.contacts[0].contact_id.clone());
                    } else if let Some(selected) = &self.selected_contact_id {
                        if !self.contacts.iter().any(|c| &c.contact_id == selected) {
                            self.selected_contact_id =
                                self.contacts.first().map(|c| c.contact_id.clone());
                        }
                    }

                    if let Some(cid) = self.selected_contact_id.clone() {
                        self.send(Command::LoadMessages { contact_id: cid });
                    } else {
                        self.messages.clear();
                    }

                    self.set_status("Contacts refreshed.");
                }
                Err(e) => self.set_status(format!("Loading contacts failed: {e}")),
            },

            WorkerEvent::Messages {
                contact_id,
                result,
                note,
            } => match result {
                Ok(page) => {
                    let _ = (page.paging.has_more, page.paging.next_before_id);
                    if self.selected_contact_id.as_deref() == Some(contact_id.as_str()) {
                        self.messages = page.messages;
                    }
                    if let Some(note) = note {
                        self.set_status(note);
                    } else {
                        self.set_status("Messages refreshed.");
                    }
                }
                Err(e) => self.set_status(format!("Loading messages failed: {e}")),
            },

            WorkerEvent::CreateInvite(res) => match res {
                Ok(v) => {
                    self.generated_invite_code = v.code;
                    self.pending_select_contact_id = Some(v.contact_id);
                    self.set_status("Invite created.");
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.set_status(format!("Create invite failed: {e}")),
            },

            WorkerEvent::AcceptInvite(res) => match res {
                Ok(v) => {
                    let _ = v.my_code;
                    self.generated_invite_code.clear();
                    self.pending_select_contact_id = Some(v.contact_id);
                    self.invite_code_input.clear();
                    self.confirm_wipe_local = false;
                    self.set_status("Invite accepted.");
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.set_status(format!("Accept invite failed: {e}")),
            },

            WorkerEvent::ForgetContact { contact_id, result } => match result {
                Ok(()) => {
                    if self.selected_contact_id.as_deref() == Some(contact_id.as_str()) {
                        self.selected_contact_id = None;
                        self.messages.clear();
                    }
                    self.confirm_wipe_local = false;
                    self.set_status("Contact removed.");
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.set_status(format!("Forget contact failed: {e}")),
            },

            WorkerEvent::WipeLocal(res) => match res {
                Ok(()) => {
                    self.screen = Screen::Connecting;
                    self.confirm_wipe_local = false;

                    self.data_password.clear();
                    self.data_password_confirm.clear();
                    self.handler.clear();
                    self.account_password.clear();
                    self.account_password_confirm.clear();

                    self.contacts.clear();
                    self.selected_contact_id = None;
                    self.messages.clear();
                    self.message_text.clear();

                    self.invite_code_input.clear();
                    self.invite_label_input.clear();
                    self.generated_invite_code.clear();
                    self.pending_select_contact_id = None;

                    self.set_status("Local data wiped.");
                    self.send(Command::Ping);
                }
                Err(e) => {
                    self.confirm_wipe_local = false;
                    self.set_status(format!("Wipe local failed: {e}"));
                }
            },
        }
    }

    fn draw_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(&self.status_line);

            if self.busy {
                ui.separator();
                ui.spinner();
            }

            ui.separator();

            if ui.button("Retry / Refresh").clicked() && !self.busy {
                self.confirm_wipe_local = false;
                self.send(Command::Ping);
            }

            ui.separator();

            let wipe_label = if self.confirm_wipe_local {
                "Confirm wipe local"
            } else {
                "Wipe local"
            };

            if ui
                .add_enabled(!self.busy, egui::Button::new(wipe_label))
                .clicked()
            {
                if self.confirm_wipe_local {
                    self.confirm_wipe_local = false;
                    self.send(Command::WipeLocal);
                } else {
                    self.confirm_wipe_local = true;
                    self.set_status("Click 'Confirm wipe local' to remove all local daemon data.");
                }
            }

            if self.confirm_wipe_local {
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Cancel wipe"))
                    .clicked()
                {
                    self.confirm_wipe_local = false;
                    self.set_status("Wipe cancelled.");
                }
            }
        });
    }

    fn draw_set_data_password(&mut self, ui: &mut egui::Ui) {
        ui.heading("Set data password");
        ui.label("This looks like the first run. Set the local data password for the daemon.");

        ui.add(
            egui::TextEdit::singleline(&mut self.data_password)
                .password(true)
                .hint_text("Data password"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.data_password_confirm)
                .password(true)
                .hint_text("Repeat data password"),
        );

        let can_submit = !self.busy
            && !self.data_password.is_empty()
            && self.data_password == self.data_password_confirm;

        if ui
            .add_enabled(can_submit, egui::Button::new("Set password"))
            .clicked()
        {
            let pw = self.data_password.clone();
            self.send(Command::UnlockKeystore { data_password: pw });
        }
    }

    fn draw_unlock_data_password(&mut self, ui: &mut egui::Ui) {
        ui.heading("Unlock keystore");
        ui.label("Enter your existing data password.");

        ui.add(
            egui::TextEdit::singleline(&mut self.data_password)
                .password(true)
                .hint_text("Data password"),
        );

        let can_submit = !self.busy && !self.data_password.is_empty();

        if ui
            .add_enabled(can_submit, egui::Button::new("Unlock"))
            .clicked()
        {
            let pw = self.data_password.clone();
            self.send(Command::UnlockKeystore { data_password: pw });
        }
    }

    fn draw_credentials(&mut self, ui: &mut egui::Ui) {
        ui.heading("Account credentials");
        ui.label("Enter handler and account password.");

        ui.add(
            egui::TextEdit::singleline(&mut self.handler)
                .hint_text("Handler"),
        );

        ui.add(
            egui::TextEdit::singleline(&mut self.account_password)
                .password(true)
                .hint_text("Account password"),
        );

        ui.add(
            egui::TextEdit::singleline(&mut self.account_password_confirm)
                .password(true)
                .hint_text("Repeat account password"),
        );

        if !self.account_password_confirm.is_empty()
            && self.account_password != self.account_password_confirm
        {
            ui.label("Passwords do not match.");
        }

        let can_submit = !self.busy
            && !self.handler.trim().is_empty()
            && !self.account_password.is_empty()
            && self.account_password == self.account_password_confirm;

        if ui
            .add_enabled(can_submit, egui::Button::new("Save credentials"))
            .clicked()
        {
            self.send(Command::SetCredentials {
                handler: self.handler.trim().to_string(),
                password: self.account_password.clone(),
            });
        }
    }

    fn draw_register(&mut self, ui: &mut egui::Ui) {
        ui.heading("Register");
        ui.label("The daemon is ready, but the account still needs registration.");

        if ui
            .add_enabled(!self.busy, egui::Button::new("Register"))
            .clicked()
        {
            self.send(Command::Register);
        }
    }

    fn draw_unlock_storage(&mut self, ui: &mut egui::Ui) {
        ui.heading("Unlock storage");
        ui.label("Finish local storage initialization.");

        if ui
            .add_enabled(!self.busy, egui::Button::new("Unlock storage"))
            .clicked()
        {
            self.send(Command::UnlockStorage);
        }
    }

    fn draw_ready(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let narrow = ui.available_width() < 760.0;

        if narrow {
            ui.vertical(|ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    self.draw_contacts_panel(ui, true);
                });

                ui.add_space(8.0);

                egui::Frame::default().show(ui, |ui| {
                    self.draw_messages_panel(ui);
                });
            });
        } else {
            egui::SidePanel::left("contacts_panel")
                .resizable(true)
                .default_width(320.0)
                .min_width(260.0)
                .max_width(520.0)
                .show_inside(ui, |ui| {
                    self.draw_contacts_panel(ui, false);
                });

            egui::CentralPanel::default().show_inside(ui, |ui| {
                self.draw_messages_panel(ui);
            });
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn draw_invite_box(
        ui: &mut egui::Ui,
        id: &'static str,
        text: &mut String,
        hint: &str,
        interactive: bool,
    ) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            if !interactive {
                ui.horizontal(|ui| {
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(text.clone());
                    }
                });
            }

            egui::ScrollArea::both()
                .id_source(id)
                .max_height(96.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if interactive {
                        ui.add(
                            egui::TextEdit::multiline(text)
                                .desired_rows(3)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace)
                                .hint_text(hint),
                        );
                    } else {
                        let mut preview = text.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut preview)
                                .desired_rows(3)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                    }
                });
        });
    }

    fn draw_contacts_panel(&mut self, ui: &mut egui::Ui, compact: bool) {
        ui.heading("Contacts");

        ui.horizontal_wrapped(|ui| {
            if ui.button("Refresh").clicked() && !self.busy {
                self.send(Command::LoadContacts);
            }

            if ui.button("New invite").clicked() && !self.busy {
                self.send(Command::CreateInvite { contact_id: None });
            }

            let can_reply_for_selected = !self.busy && self.selected_contact_id.is_some();
            if ui
                .add_enabled(
                    can_reply_for_selected,
                    egui::Button::new("Reply to invite for selected"),
                )
                .clicked()
            {
                self.send(Command::CreateInvite {
                    contact_id: self.selected_contact_id.clone(),
                });
            }
        });

        if !self.generated_invite_code.is_empty() {
            ui.separator();
            ui.label("Generated invite code:");
            Self::draw_invite_box(
                ui,
                "generated_invite_scroll",
                &mut self.generated_invite_code,
                "",
                false,
            );
        }

        ui.separator();
        ui.label("Add contact from invite");

        ui.add_sized(
            [ui.available_width(), 24.0],
            egui::TextEdit::singleline(&mut self.invite_label_input)
                .hint_text("Contact label"),
        );

        Self::draw_invite_box(
            ui,
            "invite_input_scroll",
            &mut self.invite_code_input,
            "Paste invite code",
            true,
        );

        let can_accept = !self.busy
            && !self.invite_label_input.trim().is_empty()
            && !self.invite_code_input.trim().is_empty();

        if ui
            .add_enabled(can_accept, egui::Button::new("Add contact"))
            .clicked()
        {
            let target_contact_id = self
                .selected_contact()
                .filter(|c| !c.peer_set)
                .map(|c| c.contact_id.clone());

            self.send(Command::AcceptInvite {
                code: self.invite_code_input.trim().to_string(),
                label: self.invite_label_input.trim().to_string(),
                contact_id: target_contact_id,
            });
        }

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

                let mut label = if contact.label.is_empty() {
                    contact.contact_id.clone()
                } else {
                    contact.label.clone()
                };

                if !contact.peer_set {
                    label.push_str(" (invite pending)");
                }

                if ui
                    .add_sized(
                        [ui.available_width(), 22.0],
                        egui::SelectableLabel::new(is_selected, label),
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
        ui.heading("Messages");

        let selected = self.selected_contact().cloned();

        if let Some(contact) = selected {
            ui.horizontal_wrapped(|ui| {
                let title = if contact.label.is_empty() {
                    contact.contact_id.clone()
                } else {
                    contact.label.clone()
                };
                ui.label(title);

                if !contact.peer_set {
                    ui.separator();
                    ui.label("Peer not fully set yet");
                }

                if !contact.peer_cid.is_empty() {
                    ui.separator();
                    ui.label(format!("peer_cid: {}", contact.peer_cid));
                }
            });

            ui.horizontal_wrapped(|ui| {
                if ui.button("Fetch").clicked() && !self.busy {
                    self.send(Command::FetchMessages {
                        contact_id: contact.contact_id.clone(),
                    });
                }

                if ui.button("Reload history").clicked() && !self.busy {
                    self.send(Command::LoadMessages {
                        contact_id: contact.contact_id.clone(),
                    });
                }

                if ui.button("Forget contact").clicked() && !self.busy {
                    self.send(Command::ForgetContact {
                        contact_id: contact.contact_id.clone(),
                    });
                }
            });

            ui.separator();

            let list_height = (ui.available_height() - 140.0).max(120.0);

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(list_height)
                .show(ui, |ui| {
                    for msg in &self.messages {
                        let who = if msg.direction == "out" { "You" } else { "Peer" };
                        let text = msg.text.clone().unwrap_or_else(|| "<non-text>".into());
                        let _ = (&msg.kind, &msg.ui);

                        ui.group(|ui| {
                            ui.label(format!("{who} · {} · {}", msg.created_at, msg.id));
                            ui.label(text);
                        });
                        ui.add_space(6.0);
                    }
                });

            ui.separator();

            ui.label("Compose");
            ui.add(
                egui::TextEdit::multiline(&mut self.message_text)
                    .desired_rows(4)
                    .hint_text("Type message"),
            );

            let can_send = !self.busy && !self.message_text.trim().is_empty();

            if ui
                .add_enabled(can_send, egui::Button::new("Send"))
                .clicked()
            {
                let text = self.message_text.trim().to_string();
                self.message_text.clear();
                self.send(Command::SendMessage {
                    contact_id: contact.contact_id.clone(),
                    plaintext: text,
                });
            }
        } else {
            ui.label("Select a contact.");
        }
    }

}

impl eframe::App for LithiumApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            self.draw_top_bar(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.screen {
            Screen::Connecting => {
                ui.heading("Connecting");
                ui.label("Waiting for daemon...");
            }
            Screen::DaemonOffline => {
                ui.heading("Daemon offline");
                ui.label("Could not reach lithiumd.");
                if ui.button("Retry").clicked() && !self.busy {
                    self.send(Command::Ping);
                }
            }
            Screen::SetDataPassword => self.draw_set_data_password(ui),
            Screen::UnlockDataPassword => self.draw_unlock_data_password(ui),
            Screen::Credentials => self.draw_credentials(ui),
            Screen::Register => self.draw_register(ui),
            Screen::UnlockStorage => self.draw_unlock_storage(ui),
            Screen::Ready => self.draw_ready(ctx, ui),
        });
    }
}

fn summarize_fetch_result(fetch: &ipc::ContactFetchResult) -> String {
    let total = fetch.messages.len();
    if total == 0 {
        return "Fetch complete: mailbox empty.".to_string();
    }

    let mut ok_count = 0usize;
    let mut err_count = 0usize;
    let mut err_kinds = std::collections::BTreeMap::<String, usize>::new();

    for item in &fetch.messages {
        if item.ok {
            ok_count += 1;
        } else {
            err_count += 1;
            let key = item.err.clone().unwrap_or_else(|| "unknown".to_string());
            *err_kinds.entry(key).or_insert(0) += 1;
        }
    }

    if err_count == 0 {
        format!("Fetch complete: imported {ok_count} message(s).")
    } else {
        let details = err_kinds
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");

        format!(
            "Fetch complete: ok={ok_count}, err={err_count} [{}]",
            details
        )
    }
}

pub async fn handle_command(cmd: Command) -> WorkerEvent {
    match cmd {
        Command::Ping => WorkerEvent::Ping(ipc::ping().await),

        Command::UnlockKeystore { data_password } => {
            WorkerEvent::UnlockKeystore(ipc::unlock_keystore(&data_password).await)
        }

        Command::SetCredentials { handler, password } => {
            WorkerEvent::SetCredentials(ipc::set_credentials(&handler, &password).await)
        }

        Command::Register => WorkerEvent::Register(ipc::register().await),

        Command::UnlockStorage => WorkerEvent::UnlockStorage(ipc::unlock_storage().await),

        Command::LoadContacts => WorkerEvent::Contacts(ipc::contacts_list().await),

        Command::LoadMessages { contact_id } => {
            let res = ipc::messages_list(&contact_id, 100, None).await;
            WorkerEvent::Messages {
                contact_id,
                result: res,
                note: None,
            }
        }

        Command::SendMessage { contact_id, plaintext } => {
            let res = match ipc::contact_send(&contact_id, &plaintext).await {
                Ok(()) => ipc::messages_list(&contact_id, 100, None).await,
                Err(e) => Err(e),
            };

            WorkerEvent::Messages {
                contact_id,
                result: res,
                note: Some("Message sent.".into()),
            }
        }

        Command::FetchMessages { contact_id } => {
            let fetch_note = match ipc::contact_fetch(&contact_id).await {
                Ok(fetch) => summarize_fetch_result(&fetch),
                Err(e) => format!("Fetch failed: {e}"),
            };

            let res = ipc::messages_list(&contact_id, 100, None).await;

            WorkerEvent::Messages {
                contact_id,
                result: res,
                note: Some(fetch_note),
            }
        }

        Command::CreateInvite { contact_id } => {
            WorkerEvent::CreateInvite(ipc::create_invite(contact_id.as_deref()).await)
        }

        Command::AcceptInvite { code, label, contact_id } => {
            WorkerEvent::AcceptInvite(ipc::accept_invite(&code, &label, contact_id.as_deref()).await)
        }

        Command::ForgetContact { contact_id } => {
            let res = ipc::contact_forget(&contact_id).await;
            WorkerEvent::ForgetContact { contact_id, result: res }
        }

        Command::WipeLocal => WorkerEvent::WipeLocal(ipc::wipe_local().await),
    }
}
