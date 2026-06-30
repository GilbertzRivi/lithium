# lithiumg: the Lithium GUI

The GUI client of the Lithium messenger, built on eframe and egui. 
It talks to the local `lithiumd` daemon over IPC (Unix socket / 
Windows named pipe). It performs no cryptographic operations 
itself, everything is delegated to the daemon.

## Place in the architecture

```
lithiumg (GUI)   <- this crate
  | JSON-lines / Unix socket or Windows named pipe
lithiumd (daemon)
  | HTTPS + KyberBox
lithiums (relay server)
```

## Running

```bash
# Linux/macOS, the daemon must be running
lithiumd &
lithiumg
```

Environment variables (optional):

| Variable | Default (Linux) | Description |
|----------|-----------------|-------------|
| `LITHIUMD_SOCKET_PATH` | `$XDG_RUNTIME_DIR/lithiumd.sock` | Unix socket path |
| `LITHIUMD_PIPE_NAME` | `\\.\pipe\lithiumd` | Named pipe name (Windows) |

Socket location priority (Linux):
1. `LITHIUMD_SOCKET_PATH`
2. `$XDG_RUNTIME_DIR/lithiumd.sock`

Without a safe location there is no fallback, the connection fails 
and the GUI shows `DaemonOffline`.

---

## Application architecture

Module structure:

```
src/
  main.rs    entry point: mpsc channels, worker thread, emoji font install, eframe
  app/       UI logic: screen state machine, rendering, event handling
    mod.rs       LithiumApp, Command, Screen, the render loop
    screens.rs   onboarding screens
    chat.rs      the message panel
    topbar.rs    the top bar
    modals.rs    modals (including verify emoji)
    events.rs    WorkerEvent handling
  ipc.rs     IPC layer: JSON over socket/pipe, auth token, response types
  errors.rs  mapping daemon error codes to user messages
```

### Thread model

```
Main thread (egui event loop)
  - Sends Command via cmd_tx
  - Reads WorkerEvent via rx.try_recv() (non-blocking)
  - Renders the screen from state

         | mpsc (two channels)

Worker thread (tokio runtime)
  - Reads Command from cmd_rx
  - Performs the IPC call (async)
  - Sends WorkerEvent via evt_tx
```

The GUI never blocks, all IPC operations run on a separate thread 
with a tokio runtime. The main thread polls the channel every 
render frame; in the Ready screen it forces a refresh at least 
every 1 s, and auto-refreshes the message history every 3 s.

---

## State machine: screens

The app moves between screens based on the `ui_state` field 
returned by the daemon's `ping`:

```
Connecting
  | ping success
  +-> SetDataPassword      (first_run=true, no keystore on disk)
  +-> UnlockDataPassword   (keystore on disk, locked)
  +-> Credentials          (ui_state="needs_credentials")
  +-> Register             (ui_state="needs_register")
  +-> UnlockStorage        (ui_state="storage_locked")
  +-> Ready                (ui_state="ready")

  DaemonOffline            (ping failed)
```

| Screen | Description |
|--------|-------------|
| `Connecting` | Initial state, waiting for the daemon's response |
| `DaemonOffline` | The daemon is unreachable |
| `SetDataPassword` | First run, set the keystore password (2x confirm) |
| `UnlockDataPassword` | Unlock the existing keystore with a password |
| `Credentials` | Enter the handler and the server account password (2x confirm when new) |
| `Register` | Register the profile on the server, one click |
| `UnlockStorage` | Initialize the local storage (SQLite) |
| `Ready` | The main screen: contact list + message history |

---

## The Ready screen: layout

The Ready screen has two variants depending on the window width 
(threshold: 760px):

**Wide window (>=760px):**
```
+----------------------------------------------------------+
| TOP BAR: status . [Retry/Refresh] . [Wipe local]         |
+---------------------+------------------------------------+
|  CONTACTS PANEL     |  MESSAGE PANEL                     |
|  (resizable, 260-   |                                    |
|   520px)            |  Header + [Refresh] [Remove]       |
|                     |                                    |
|  [Refresh]          |  +------------------------------+  |
|  [New invite]       |  | Message history              |  |
|  [Reply] (if a      |  | (scroll area)                |  |
|   contact is sel.)  |  |                              |  |
|                     |  | Verify emoji modal           |  |
|  Add contact:       |  | (if the peer is new)         |  |
|  Label: [input]     |  +------------------------------+  |
|  Code: [textarea]   |                                    |
|  [Add contact]      |  Compose:                          |
|                     |  [multiline input]                 |
|  Contacts:          |  [Send]                            |
|  ( ) Alice          |                                    |
|  (*) Bob            |                                    |
|  ( ) Carol          |                                    |
+---------------------+------------------------------------+
```

**Narrow window (<760px):** a vertical layout, the contacts panel 
above the message panel.

### Top bar

Always visible. It holds:
- The current status (the result of the last operation)
- A loading indicator (a spinner when `busy=true`)
- `[Retry / Refresh]`, re-ping + state refresh
- `[Wipe local]`, a two-step confirmation (the first click changes 
  the label to `[Confirm wipe local]`)

### Contacts panel

- `[Refresh]`, refreshes the contact list
- `[New invite]`, creates a new invite (generates an `lci1:...` 
  code)
- `[Reply]`, replies to an invite for the selected contact (fills 
  in their keys)
- A section for adding a contact from an invite code: a label + a 
  textarea for the code
- The contact list as buttons (highlighted = selected)

### Message panel

- A header with the contact's name and whether the peer is set 
  (`peer_set`)
- `[Refresh]`, reloads the history from the local database 
  (incoming messages arrive on their own through background 
  auto-fetch)
- `[Remove contact]`, removes the contact
- The message history in a scroll area; each message: `You/Peer . 
  timestamp . id` + content
- A compose field (multiline) + `[Send]` (active only when 
  `peer_set=true` and the text is non-empty)

### Verify emoji modal

It appears automatically when:
- `peer_set=true`
- there are no outgoing messages (the peer hasn't replied yet)
- it hasn't been shown for this contact yet

It displays an emoji string to verify over an out-of-band channel 
(for example over the phone). The `[Hide]` button closes the 
modal; it shows only once per contact per session.

---

## IPC: talking to lithiumd

The transport (Unix socket / named pipe on Windows), the 
JSON-lines request and response format, and the full command 
contract and error codes are in 
[ipc-reference.md](../protocol/ipc-reference.md). Below is only the 
GUI-specific part: client-side token storage, the subset of 
commands relevant to the UI, and the deserialized response types.

### Auth token

After the keystore is unlocked the daemon returns an 
`ipc_auth_token`. The token is held in 
`OnceLock<Mutex<Option<String>>>` and automatically attached to 
every subsequent request. Cleared when:
- the daemon replies `ipc_auth_failed` or `ipc_auth_required`
- `wipe_local` was performed

### IPC commands

Full reference: [ipc-reference.md](../protocol/ipc-reference.md). 
The commands relevant to the GUI:

| Command | Description | Key request fields | Response |
|---------|-------------|--------------------|----------|
| `ping` | Check the daemon state | - | `ui_state`, `status.*` |
| `unlock_keystore` | Unlock the keystore with a password | `data_password` | `ipc_auth_token` |
| `lock_keystore` | Lock the keystore (zeroize) | - | - |
| `set_credentials` | Set the handler + account password | `handler`, `password` | - |
| `set_server_url` | Set the relay address | `url` | - |
| `set_server_identity` | Set the server identity (hex) | `data` | - |
| `register` | Register the profile on the server | - | - |
| `unlock_storage` | Initialize the local storage | - | - |
| `contacts_list` | Get the contact list | - | `contacts[]` |
| `messages_list` | Get the message history | `contact_id`, `limit`, `before_id` | `messages[]`, `paging` |
| `contact_send` | Send a message | `contact_id`, `plaintext` | - |
| `create_invite` | Pairing step 1: create the commitment | `contact_id` (opt.) | `contact_id`, `commitment` |
| `accept_commitment` | Step 2: accept the commitment, return your code | `commitment`, `label` | `contact_id`, `code` |
| `reveal_invite` | Step 3: reveal your code after the peer's code | `contact_id`, `peer_code`, `label` | `code` |
| `finalize_pairing` | Step 4: verify the peer's code | `contact_id`, `peer_code` | `ok` |
| `contact_verify_emoji` | Get the verification emoji | `contact_id` | `emojis[]` |
| `contact_forget` | Remove a contact | `contact_id` | - |
| `delete_account` | Delete the account on the server + locally | - | - |
| `wipe_local` | Wipe all local data | - | - |
| `shutdown` | Shut the daemon down | - | - |

Manual fetch doesn't exist, incoming messages are fetched in the 
background by the daemon (cover traffic), and the GUI refreshes the 
view through `messages_list` from the local database (auto-refresh 
every 3 s).

### Response types

```rust
PingResult {
    pong: bool,
    ui_state: String,           // "keystore_locked" | "needs_credentials" | ...
    status: PingStatus {
        has_keystore_on_disk: bool,
        has_local_db: bool,
        has_proto: bool,
        has_credentials: bool,
        needs_register: bool,
        // ... and other state flags
    },
    actions_needed: Vec<String>,
}

ContactInfo {
    contact_id: String,
    label: String,
    peer_set: bool,    // whether the other side has accepted the invite
    peer_cid: String,
}

MessageItem {
    id: i64,
    direction: String,          // "in" | "out"
    kind: String,               // "text" | ...
    text: Option<String>,
    ui: Value,                  // UI metadata (mailbox_gen, etc.)
    created_at: String,
}

CreateInviteResult     { contact_id: String, commitment: String }
AcceptCommitmentResult { contact_id: String, code: String }
RevealInviteResult     { code: String }
VerifyEmojiResult      { emojis: Vec<String> }
```

---

## Contact invite flow

The GUI walks the user through the four-step commit-reveal, whose 
order the daemon enforces: `create_invite` -> `accept_commitment` 
-> `reveal_invite` -> `finalize_pairing`. The commitment and the 
codes (`lci1:`) are passed out-of-band between devices by the user. 
The full flow with request fields and the commitment verification 
rule is in [ipc-reference.md](../protocol/ipc-reference.md); the 
pairing cryptography (SAS, identity transcript) is in 
[crypto-protocol.md](../protocol/crypto-protocol.md).

## Implementation details

### Emoji font (Linux)

At startup the app looks for an emoji font in system locations:
```
/usr/share/fonts/truetype/noto/NotoEmoji-Regular.ttf
/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf
/usr/share/fonts/truetype/ancient-scripts/Symbola_hint.ttf
/usr/share/fonts/TTF/Symbola.ttf
```
If none is found, emoji render as squares.

### UI blocking (`busy`)

The `busy=true` flag is set on every command send; reset when 
`drain_events()` receives the response. All buttons are disabled 
when `busy=true`.

### Contact auto-selection

After the contact list loads:
- If none was selected, the first is selected automatically
- If the selected contact disappeared (for example after 
  `forget`), the selection moves to the first available one
- After `create_invite` / `accept_commitment`, the new contact is 
  selected automatically

### Message pagination

`messages_list` takes `limit` and `before_id` (for paging). The 
current GUI implementation loads the last 100 messages 
(`limit=100`, `before_id=None`).
