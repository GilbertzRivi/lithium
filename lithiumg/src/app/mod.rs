use std::{
    collections::HashSet,
    sync::mpsc::{Receiver, Sender},
};

/// Zero then clear a String to reduce the time sensitive data lives in memory.
pub(super) fn zero_str(s: &mut String) {
    // SAFETY: we immediately clear length to 0, so the zeroed bytes are never read as UTF-8.
    unsafe { s.as_mut_vec().fill(0) };
    s.clear();
}

use eframe::egui;

use crate::ipc::{
    AcceptInviteResult, ContactInfo, CreateInviteResult, MessageItem, MessagesResult, PingResult,
    RegisterResult, VerifyEmojiResult,
};

mod chat;
mod events;
mod modals;
mod screens;
mod topbar;

pub use events::handle_command;

#[derive(Debug, Clone)]
pub enum Command {
    Ping,
    UnlockKeystore { data_password: String },
    SetCredentials { username: String, password: String },
    Register,
    RemoteDelete { capability: String },
    DeleteAccount,
    UnlockStorage,
    LoadContacts,
    LoadMessages { contact_id: String },
    SendMessage { contact_id: String, plaintext: String },
    FetchMessages { contact_id: String },
    CreateInvite { contact_id: Option<String> },
    AcceptInvite { code: String, label: String, contact_id: Option<String> },
    ForgetContact { contact_id: String },
    LoadVerifyEmoji { contact_id: String },
    WipeLocal,
    LockKeystore,
}

#[derive(Debug)]
pub enum WorkerEvent {
    Ping(Result<PingResult, String>),
    UnlockKeystore(Result<(), String>),
    SetCredentials(Result<(), String>),
    Register(Result<RegisterResult, String>),
    RemoteDelete(Result<(), String>),
    DeleteAccount(Result<(), String>),
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
    VerifyEmoji {
        contact_id: String,
        result: Result<VerifyEmojiResult, String>,
    },
    WipeLocal(Result<(), String>),
    LockKeystore(Result<(), String>),
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
    status: String,
    status_is_error: bool,
    last_ping: Option<PingResult>,

    data_password: String,
    data_password_confirm: String,

    username: String,
    account_password: String,
    account_password_confirm: String,

    contacts: Vec<ContactInfo>,
    selected_contact_id: Option<String>,
    messages: Vec<MessageItem>,
    message_text: String,

    invite_code_input: String,
    invite_label_input: String,
    generated_invite_code: String,

    pending_select_contact_id: Option<String>,
    wipe_modal_open: bool,

    pending_verify_contact_id: Option<String>,
    verify_modal_open: bool,
    verify_modal_contact_id: Option<String>,
    verify_modal_emojis: Vec<String>,
    shown_verify_for_contact_ids: HashSet<String>,

    register_capability: String,
    show_register_capability_modal: bool,

    remote_delete_modal_open: bool,
    remote_delete_capability_input: String,
    confirm_remote_delete: bool,

    delete_account_modal_open: bool,
    confirm_delete_account: bool,
}

impl LithiumApp {
    pub fn new(tx: Sender<Command>, rx: Receiver<WorkerEvent>) -> Self {
        let mut app = Self {
            tx,
            rx,
            screen: Screen::Connecting,
            busy: false,
            status: "Connecting to daemon...".into(),
            status_is_error: false,
            last_ping: None,
            data_password: String::new(),
            data_password_confirm: String::new(),
            username: String::new(),
            account_password: String::new(),
            account_password_confirm: String::new(),
            contacts: Vec::new(),
            selected_contact_id: None,
            messages: Vec::new(),
            message_text: String::new(),
            invite_code_input: String::new(),
            invite_label_input: String::new(),
            generated_invite_code: String::new(),
            pending_select_contact_id: None,
            pending_verify_contact_id: None,
            verify_modal_open: false,
            verify_modal_contact_id: None,
            verify_modal_emojis: Vec::new(),
            shown_verify_for_contact_ids: HashSet::new(),
            wipe_modal_open: false,
            register_capability: String::new(),
            show_register_capability_modal: false,
            remote_delete_modal_open: false,
            remote_delete_capability_input: String::new(),
            confirm_remote_delete: false,
            delete_account_modal_open: false,
            confirm_delete_account: false,
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
        self.status = s.into();
        self.status_is_error = false;
    }

    fn set_error<S: Into<String>>(&mut self, s: S) {
        self.status = s.into();
        self.status_is_error = true;
    }

    fn drain_events(&mut self) {
        while let Ok(evt) = self.rx.try_recv() {
            self.busy = false;
            self.handle_event(evt);
        }
    }

    fn clear_verify_modal(&mut self) {
        self.verify_modal_open = false;
        self.verify_modal_contact_id = None;
        self.verify_modal_emojis.clear();
    }

    fn open_remote_delete_modal(&mut self) {
        self.remote_delete_modal_open = true;
        self.confirm_remote_delete = false;
        if self.remote_delete_capability_input.trim().is_empty()
            && !self.register_capability.is_empty()
        {
            self.remote_delete_capability_input = self.register_capability.clone();
        }
    }

    fn open_delete_account_modal(&mut self) {
        self.delete_account_modal_open = true;
        self.confirm_delete_account = false;
    }
}

/// Shared invite / capability text box used in contacts panel and modals.
pub(crate) fn draw_invite_box(
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
            .id_salt(id)
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

impl eframe::App for LithiumApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            self.draw_top_bar(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.screen {
            Screen::Connecting => {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.spinner();
                        ui.add_space(8.0);
                        ui.label("Connecting to daemon...");
                    });
                });
            }
            Screen::DaemonOffline => {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.heading("Not connected");
                    ui.add_space(8.0);
                    ui.label("Could not reach lithiumd.");
                    ui.add_space(16.0);
                    if ui.button("Retry").clicked() && !self.busy {
                        self.send(Command::Ping);
                    }
                });
            }
            Screen::SetDataPassword => self.draw_set_data_password(ui),
            Screen::UnlockDataPassword => self.draw_unlock_data_password(ui),
            Screen::Credentials => self.draw_credentials(ui),
            Screen::Register => self.draw_register(ui),
            Screen::UnlockStorage => self.draw_unlock_storage(ui),
            Screen::Ready => self.draw_ready(ctx, ui),
        });

        self.draw_wipe_modal(ctx);
        self.draw_register_capability_window(ctx);
        self.draw_remote_delete_window(ctx);
        self.draw_delete_account_window(ctx);
    }
}