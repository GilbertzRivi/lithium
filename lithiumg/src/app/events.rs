use crate::{errors, ipc};

use super::{Command, LithiumApp, PairingStep, Screen, WorkerEvent};

impl LithiumApp {
    pub(super) fn handle_ping(&mut self, ping: ipc::PingResult) {
        let s = &ping.status;
        self.mk_rotation_error = s.mk_rotation_error;
        self.last_ping = Some(ping.clone());

        if !s.has_server_url {
            self.screen = Screen::SetServerUrl;
            self.set_status("Enter the server URL to continue.");
            return;
        }

        if !s.has_server_identity {
            self.screen = Screen::SetServerIdentity;
            self.set_status("Upload the server.identity file to connect to your Lithium server.");
            return;
        }

        let has_ipc_auth = ipc::has_auth_token();

        self.screen = if ping.ui_state != "keystore_locked" && !has_ipc_auth {
            Screen::UnlockDataPassword
        } else {
            match ping.ui_state.as_str() {
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
            }
        };

        let status = if ping.ui_state != "keystore_locked" && !has_ipc_auth {
            "Session expired — re-enter your data password to continue.".to_string()
        } else {
            match self.screen {
                Screen::Connecting => "Connecting...".to_string(),
                Screen::DaemonOffline => "Daemon offline or not responding.".to_string(),
                Screen::SetServerUrl => "Enter the server URL to continue.".to_string(),
                Screen::SetServerIdentity => {
                    "Upload the server.identity file to connect to your Lithium server.".to_string()
                }
                Screen::SetDataPassword => {
                    if s.first_run {
                        "First run — set a data password to protect your local keys.".to_string()
                    } else {
                        "No local keystore found. Set a new data password to reinitialize."
                            .to_string()
                    }
                }
                Screen::UnlockDataPassword => {
                    "Enter your data password to unlock the keystore.".to_string()
                }
                Screen::Credentials => "Enter your account credentials.".to_string(),
                Screen::Register => {
                    "Account not registered yet — register before continuing.".to_string()
                }
                Screen::UnlockStorage => "Unlocking local storage...".to_string(),
                Screen::Ready => "Ready.".to_string(),
            }
        };

        self.set_status(status);

        if self.screen == Screen::Ready {
            self.send(Command::LoadContacts);
        }
    }

    pub(super) fn handle_event(&mut self, evt: WorkerEvent) {
        match evt {
            WorkerEvent::Ping(res) => match res {
                Ok(ping) => self.handle_ping(ping),
                Err(e) => {
                    self.last_ping = None;
                    self.screen = Screen::DaemonOffline;
                    self.set_error(format!("Cannot connect: {}", errors::translate(&e)));
                }
            },

            WorkerEvent::UnlockKeystore(res) => match res {
                Ok(()) => {
                    self.data_password_confirm.clear();
                    self.set_status("Keystore unlocked.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_error(errors::translate(&e)),
            },

            WorkerEvent::SetCredentials(res) => match res {
                Ok(()) => {
                    self.account_password_confirm.clear();
                    self.set_status("Credentials saved.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_error(errors::translate(&e)),
            },

            WorkerEvent::Register(res) => match res {
                Ok(v) => {
                    self.register_capability = v.capability;
                    self.show_register_capability_modal = !self.register_capability.is_empty();

                    if self.register_capability.is_empty() {
                        self.set_status("Registered successfully.");
                    } else {
                        self.set_status(
                            "Registered. Save your delete capability — it will be shown now.",
                        );
                    }

                    self.send(Command::Ping);
                }
                Err(e) => self.set_error(format!("Registration failed: {}", errors::translate(&e))),
            },

            WorkerEvent::RemoteDelete(res) => match res {
                Ok(()) => {
                    self.confirm_remote_delete = false;
                    self.remote_delete_modal_open = false;
                    self.set_status(
                        "Removal request sent. The server always responds with success regardless of whether the capability was valid.",
                    );
                }
                Err(e) => {
                    self.confirm_remote_delete = false;
                    self.set_error(format!("Removal request failed: {}", errors::translate(&e)));
                }
            },

            WorkerEvent::DeleteAccount(res) => match res {
                Ok(()) => {
                    self.screen = Screen::Connecting;
                    self.last_ping = None;

                    self.reset_all_state();
                    self.set_status("Account deleted.");
                    self.send(Command::Ping);
                }
                Err(e) => {
                    self.confirm_delete_account = false;
                    if e == "account_deleted_but_local_wipe_failed" {
                        self.delete_account_modal_open = false;
                        self.set_error(errors::translate(&e));
                    } else {
                        self.set_error(format!(
                            "Account deletion failed: {}",
                            errors::translate(&e)
                        ));
                    }
                }
            },

            WorkerEvent::UnlockStorage(res) => match res {
                Ok(()) => {
                    self.set_status("Storage unlocked.");
                    self.send(Command::Ping);
                }
                Err(e) => {
                    let e_lower = e.to_ascii_lowercase();

                    if e_lower.contains("register_required") {
                        self.screen = Screen::Register;
                        self.set_status(
                            "This profile needs to be registered before storage can be unlocked.",
                        );
                        return;
                    }

                    let bad_creds = e_lower.contains("invalid_credentials")
                        || e_lower.contains("bad_credentials")
                        || e_lower.contains("http_400")
                        || e_lower.contains("http_401")
                        || e_lower.contains("protocol_error");

                    if bad_creds {
                        self.screen = Screen::Credentials;
                        self.account_password.clear();
                        self.account_password_confirm.clear();
                        self.set_error(
                            "Wrong username or password — please re-enter your credentials.",
                        );
                    } else {
                        self.set_error(format!(
                            "Could not unlock storage: {}",
                            errors::translate(&e)
                        ));
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
                    } else if let Some(selected) = &self.selected_contact_id
                        && !self.contacts.iter().any(|c| &c.contact_id == selected)
                    {
                        self.selected_contact_id =
                            self.contacts.first().map(|c| c.contact_id.clone());
                    }

                    if let Some(cid) = self.pending_verify_contact_id.clone() {
                        let ready = self
                            .contacts
                            .iter()
                            .any(|c| c.contact_id == cid && c.peer_set);

                        if ready && !self.shown_verify_for_contact_ids.contains(&cid) {
                            self.pending_verify_contact_id = None;
                            self.send(Command::LoadVerifyEmoji { contact_id: cid });
                            return;
                        }
                    }

                    if let Some(cid) = self.selected_contact_id.clone() {
                        self.send(Command::LoadMessages { contact_id: cid });
                    } else {
                        self.messages.clear();
                        self.set_status("No contacts yet.");
                    }
                }
                Err(e) => self.set_error(format!(
                    "Could not load contacts: {}",
                    errors::translate(&e)
                )),
            },

            WorkerEvent::Messages {
                contact_id,
                result,
                note,
            } => match result {
                Ok(page) => {
                    let should_probe_verify =
                        if self.selected_contact_id.as_deref() == Some(contact_id.as_str()) {
                            self.messages = page.messages.clone();

                            let has_outbound = page.messages.iter().any(|m| m.direction == "out");
                            let peer_set = self
                                .contacts
                                .iter()
                                .find(|c| c.contact_id == contact_id)
                                .map(|c| c.peer_set)
                                .unwrap_or(false);

                            peer_set
                                && !has_outbound
                                && !self.verify_modal_open
                                && !self.shown_verify_for_contact_ids.contains(&contact_id)
                        } else {
                            false
                        };

                    if should_probe_verify {
                        self.send(Command::LoadVerifyEmoji {
                            contact_id: contact_id.clone(),
                        });
                        return;
                    }

                    if let Some(note) = note {
                        self.set_status(note);
                    } else {
                        self.set_status("Ready.");
                    }
                }
                Err(e) => self.set_error(format!(
                    "Could not load messages: {}",
                    errors::translate(&e)
                )),
            },

            WorkerEvent::VerifyEmoji { contact_id, result } => match result {
                Ok(v) => {
                    self.verify_modal_open = true;
                    self.verify_modal_contact_id = Some(contact_id.clone());
                    self.verify_modal_emojis = v.emojis;
                    self.shown_verify_for_contact_ids.insert(contact_id);
                    self.set_status("Compare the safety codes with your contact.");
                }
                Err(e) => {
                    self.clear_verify_modal();
                    self.set_error(format!(
                        "Could not load safety codes: {}",
                        errors::translate(&e)
                    ));
                }
            },

            WorkerEvent::CreateInvite(res) => match res {
                Ok(v) => {
                    self.pairing_contact_id = Some(v.contact_id);
                    self.pairing_artifact = v.commitment;
                    self.pairing_error = None;
                    self.pairing_step = PairingStep::InitiatorCommitment;
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.pairing_error = Some(errors::translate(&e)),
            },

            WorkerEvent::AcceptCommitment(res) => match res {
                Ok(v) => {
                    self.pairing_contact_id = Some(v.contact_id);
                    self.pairing_artifact = v.code;
                    self.pairing_peer_input.clear();
                    self.pairing_error = None;
                    self.pairing_step = PairingStep::ResponderCode;
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.pairing_error = Some(errors::translate(&e)),
            },

            WorkerEvent::RevealInvite(res) => match res {
                Ok(v) => {
                    self.pairing_artifact = v.code;
                    self.pairing_error = None;
                    self.pairing_step = PairingStep::InitiatorReveal;
                }
                Err(e) => self.pairing_error = Some(errors::translate(&e)),
            },

            WorkerEvent::FinalizePairing(res) => match res {
                Ok(_) => {
                    let cid = self.pairing_contact_id.clone();
                    self.clear_pairing_modal();
                    if let Some(cid) = cid {
                        self.pending_select_contact_id = Some(cid.clone());
                        self.pending_verify_contact_id = Some(cid);
                    }
                    self.set_status("Contact paired.");
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.pairing_error = Some(errors::translate(&e)),
            },

            WorkerEvent::ForgetContact { contact_id, result } => match result {
                Ok(()) => {
                    if self.selected_contact_id.as_deref() == Some(contact_id.as_str()) {
                        self.selected_contact_id = None;
                        self.messages.clear();
                    }
                    self.shown_verify_for_contact_ids.remove(&contact_id);
                    self.clear_verify_modal();
                    self.set_status("Contact removed.");
                    self.send(Command::LoadContacts);
                }
                Err(e) => self.set_error(format!(
                    "Could not remove contact: {}",
                    errors::translate(&e)
                )),
            },

            WorkerEvent::LockKeystore(res) => match res {
                Ok(()) => {
                    // State cleared in ipc::lock_keystore — just ping to re-detect screen.
                    self.contacts.clear();
                    self.selected_contact_id = None;
                    self.messages.clear();
                    self.message_text.clear();
                    self.clear_verify_modal();
                    self.mk_rotation_error = false;
                    self.set_status("Keystore locked.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_error(format!("Lock failed: {}", errors::translate(&e))),
            },

            WorkerEvent::SetServerUrl(res) => match res {
                Ok(()) => {
                    self.set_status("Server URL saved.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_error(format!(
                    "Failed to save server URL: {}",
                    errors::translate(&e)
                )),
            },

            WorkerEvent::SetServerIdentity(res) => match res {
                Ok(()) => {
                    self.set_status("Server identity saved.");
                    self.send(Command::Ping);
                }
                Err(e) => self.set_error(format!(
                    "Failed to save server identity: {}",
                    errors::translate(&e)
                )),
            },

            WorkerEvent::WipeLocal(res) => match res {
                Ok(()) => {
                    self.screen = Screen::Connecting;
                    self.last_ping = None;

                    self.reset_all_state();
                    self.set_status("Local data reset.");
                    self.send(Command::Ping);
                }
                Err(e) => {
                    self.set_error(format!("Reset failed: {}", errors::translate(&e)));
                }
            },
        }
    }
}

pub async fn handle_command(cmd: Command) -> WorkerEvent {
    match cmd {
        Command::Ping => WorkerEvent::Ping(ipc::ping().await),

        Command::UnlockKeystore { data_password } => {
            WorkerEvent::UnlockKeystore(ipc::unlock_keystore(&data_password).await)
        }

        Command::SetCredentials { username, password } => {
            WorkerEvent::SetCredentials(ipc::set_credentials(&username, &password).await)
        }

        Command::Register => WorkerEvent::Register(ipc::register().await),

        Command::RemoteDelete { capability } => {
            WorkerEvent::RemoteDelete(ipc::remote_delete(&capability).await)
        }

        Command::DeleteAccount => WorkerEvent::DeleteAccount(ipc::delete_account().await),

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

        Command::LoadVerifyEmoji { contact_id } => WorkerEvent::VerifyEmoji {
            contact_id: contact_id.clone(),
            result: ipc::contact_verify_emoji(&contact_id).await,
        },

        Command::SendMessage {
            contact_id,
            plaintext,
        } => {
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

        Command::CreateInvite { contact_id } => {
            WorkerEvent::CreateInvite(ipc::create_invite(contact_id.as_deref()).await)
        }

        Command::AcceptCommitment { commitment, label } => {
            WorkerEvent::AcceptCommitment(ipc::accept_commitment(&commitment, &label).await)
        }

        Command::RevealInvite {
            contact_id,
            peer_code,
            label,
        } => WorkerEvent::RevealInvite(ipc::reveal_invite(&contact_id, &peer_code, &label).await),

        Command::FinalizePairing {
            contact_id,
            peer_code,
        } => WorkerEvent::FinalizePairing(ipc::finalize_pairing(&contact_id, &peer_code).await),

        Command::ForgetContact { contact_id } => {
            let res = ipc::contact_forget(&contact_id).await;
            WorkerEvent::ForgetContact {
                contact_id,
                result: res,
            }
        }

        Command::SetServerUrl { url } => WorkerEvent::SetServerUrl(ipc::set_server_url(&url).await),

        Command::SetServerIdentity { data } => {
            WorkerEvent::SetServerIdentity(ipc::set_server_identity(&data).await)
        }

        Command::WipeLocal => WorkerEvent::WipeLocal(ipc::wipe_local().await),

        Command::LockKeystore => WorkerEvent::LockKeystore(ipc::lock_keystore().await),
    }
}
