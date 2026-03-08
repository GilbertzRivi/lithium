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
                    self.set_status("Keystore unlocked.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_status(format!("Unlock failed: {e}")),
            },

            WorkerEvent::SetCredentials(res) => match res {
                Ok(()) => {
                    self.set_status("Credentials saved.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_status(format!("Saving credentials failed: {e}")),
            },

            WorkerEvent::Register(res) => match res {
                Ok(()) => {
                    self.set_status("Registered.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_status(format!("Register failed: {e}")),
            },

            WorkerEvent::UnlockStorage(res) => match res {
                Ok(()) => {
                    self.set_status("Storage unlocked.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_status(format!("Unlock storage failed: {e}")),
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
                            self.selected_contact_id = self.contacts.first().map(|c| c.contact_id.clone());
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

            WorkerEvent::Messages { contact_id, result, note } => match result {
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
                    self.generated_invite_code = v.my_code;
                    self.pending_select_contact_id = Some(v.contact_id);
                    self.invite_code_input.clear();
                    self.set_status("Invite accepted. Share back the generated code if needed.");
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
                    self.set_status("Contact removed.");
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.set_status(format!("Forget contact failed: {e}")),
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
                self.send(Command::Ping);
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

        ui.add(egui::TextEdit::singleline(&mut self.handler).hint_text("Handler"));
        ui.add(
            egui::TextEdit::singleline(&mut self.account_password)
                .password(true)
                .hint_text("Account password"),
        );

        let can_submit = !self.busy && !self.handler.is_empty() && !self.account_password.is_empty();

        if ui
            .add_enabled(can_submit, egui::Button::new("Save credentials"))
            .clicked()
        {
            self.send(Command::SetCredentials {
                handler: self.handler.clone(),
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
        egui::SidePanel::left("contacts_panel")
            .resizable(true)
            .show_inside(ui, |ui| {
                ui.heading("Contacts");

                ui.horizontal(|ui| {
                    if ui.button("Refresh").clicked() && !self.busy {
                        self.send(Command::LoadContacts);
                    }
                    if ui.button("Create invite").clicked() && !self.busy {
                        self.send(Command::CreateInvite { contact_id: None });
                    }
                });

                if !self.generated_invite_code.is_empty() {
                    ui.separator();
                    ui.label("Generated invite code:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.generated_invite_code)
                            .desired_rows(4)
                            .lock_focus(true),
                    );
                }

                ui.separator();
                ui.label("Add contact from invite");
                ui.add(
                    egui::TextEdit::singleline(&mut self.invite_label_input)
                        .hint_text("Contact label"),
                );
                ui.add(
                    egui::TextEdit::multiline(&mut self.invite_code_input)
                        .desired_rows(4)
                        .hint_text("Paste invite code"),
                );

                let can_accept = !self.busy
                    && !self.invite_label_input.trim().is_empty()
                    && !self.invite_code_input.trim().is_empty();

                if ui
                    .add_enabled(can_accept, egui::Button::new("Add contact"))
                    .clicked()
                {
                    self.send(Command::AcceptInvite {
                        code: self.invite_code_input.trim().to_string(),
                        label: self.invite_label_input.trim().to_string(),
                        contact_id: None,
                    });
                }

                ui.separator();

                let mut clicked_contact_id: Option<String> = None;

                egui::ScrollArea::vertical().show(ui, |ui| {
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

                        if ui.selectable_label(is_selected, label).clicked() {
                            clicked_contact_id = Some(contact.contact_id.clone());
                        }
                    }
                });

                if let Some(contact_id) = clicked_contact_id {
                    self.selected_contact_id = Some(contact_id.clone());
                    self.send(Command::LoadMessages { contact_id });
                }
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("Messages");

            let selected = self.selected_contact().cloned();

            if let Some(contact) = selected {
                ui.horizontal(|ui| {
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

                ui.horizontal(|ui| {
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

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
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
                ui.label("Select a contact on the left.");
            }
        });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
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
            let res = match ipc::contact_fetch(&contact_id).await {
                Ok(()) => ipc::messages_list(&contact_id, 100, None).await,
                Err(e) => Err(e),
            };

            WorkerEvent::Messages {
                contact_id,
                result: res,
                note: Some("Fetched messages.".into()),
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
    }
}
