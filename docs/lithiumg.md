# lithiumg — interfejs graficzny Lithium

Klient GUI komunikatora Lithium oparty na eframe i egui. Komunikuje się z lokalnym daemonem `lithiumd` przez IPC
(Unix socket / Windows named pipe). Sam nie wykonuje żadnych operacji kryptograficznych — wszystko delegowane jest do daemona.

## Miejsce w architekturze

```
lithiumg (GUI)   ← ten crate
  ↕ JSON-lines / Unix socket lub Windows named pipe
lithiumd (daemon)
  ↕ HTTPS + Kyberbox
lithiums (serwer relay)
```

## Uruchomienie

```bash
# Linux/macOS — daemon musi być uruchomiony
lithiumd &
lithiumg
```

Zmienne środowiskowe (opcjonalne):

| Zmienna                | Domyślnie (Linux)                | Opis                       |
|------------------------|----------------------------------|----------------------------|
| `LITHIUMD_SOCKET_PATH` | `$XDG_RUNTIME_DIR/lithiumd.sock` | Ścieżka do Unix socketa    |
| `LITHIUMD_PIPE_NAME`   | `\\.\pipe\lithiumd`              | Nazwa named pipe (Windows) |

Priorytet lokalizacji socketa (Linux):
1. `LITHIUMD_SOCKET_PATH`
2. `$XDG_RUNTIME_DIR/lithiumd.sock`

Bez bezpiecznej lokalizacji nie ma fallbacku — połączenie zawodzi i GUI pokazuje `DaemonOffline`.

---

## Architektura aplikacji

Struktura modułów:

```
src/
├── main.rs    — punkt wejścia: kanały mpsc, worker thread, instalacja czcionki emoji, eframe
├── app/       — logika UI: maszyna stanów ekranów, rendering, obsługa zdarzeń
│   ├── mod.rs       — LithiumApp, Command, Screen, pętla renderowania
│   ├── screens.rs   — ekrany onboardingu
│   ├── chat.rs      — panel wiadomości
│   ├── topbar.rs    — górny pasek
│   ├── modals.rs    — modale (m.in. verify emoji)
│   └── events.rs    — obsługa WorkerEvent
├── ipc.rs     — warstwa IPC: JSON over socket/pipe, auth token, typy odpowiedzi
└── errors.rs  — mapowanie kodów błędów daemona na komunikaty użytkownika
```

### Model wątków

```
Wątek główny (egui event loop)
  ├─ Wysyła Command przez cmd_tx
  ├─ Czyta WorkerEvent przez rx.try_recv() (non-blocking)
  └─ Renderuje ekran na podstawie stanu

         ↕ mpsc (dwa kanały)

Wątek roboczy (tokio runtime)
  ├─ Czyta Command z cmd_rx
  ├─ Wykonuje wywołanie IPC (async)
  └─ Wysyła WorkerEvent przez evt_tx
```

GUI nigdy nie blokuje — wszystkie operacje IPC wykonywane są w osobnym wątku z runtimem tokio.
Wątek główny odpytuje kanał co klatkę renderowania; w ekranie Ready wymusza odświeżenie przynajmniej co 1 s, a historię wiadomości auto-odświeża co 3 s.

---

## Maszyna stanów — ekrany

Aplikacja przechodzi między ekranami na podstawie pola `ui_state` zwracanego przez `ping` daemona:

```
Connecting
  ↓ ping success
  ├→ SetDataPassword      (first_run=true, brak keystora na dysku)
  ├→ UnlockDataPassword   (keystore na dysku, zablokowany)
  ├→ Credentials          (ui_state="needs_credentials")
  ├→ Register             (ui_state="needs_register")
  ├→ UnlockStorage        (ui_state="storage_locked")
  └→ Ready                (ui_state="ready")

  DaemonOffline           (ping nie powiódł się)
```

| Ekran                | Opis                                                           |
|----------------------|----------------------------------------------------------------|
| `Connecting`         | Stan początkowy — oczekiwanie na odpowiedź daemona             |
| `DaemonOffline`      | Daemon nieosiągalny                                            |
| `SetDataPassword`    | Pierwsze uruchomienie — ustaw hasło do keystora (2× confirm)   |
| `UnlockDataPassword` | Odblokuj istniejący keystore hasłem                            |
| `Credentials`        | Podaj handler i hasło do konta serwera (2× confirm przy nowym) |
| `Register`           | Rejestracja profilu na serwerze — jedno kliknięcie             |
| `UnlockStorage`      | Inicjalizacja lokalnego storage (SQLite)                       |
| `Ready`              | Główny ekran: lista kontaktów + historia wiadomości            |

---

## Ekran Ready — układ

Ekran Ready ma dwa warianty zależnie od szerokości okna (próg: 760px):

**Szerokie okno (≥760px):**
```
┌──────────────────────────────────────────────────────────┐
│ TOP BAR: status · [Retry/Refresh] · [Wipe local]         │
├─────────────────────┬────────────────────────────────────┤
│  PANEL KONTAKTÓW    │  PANEL WIADOMOŚCI                  │
│  (resizable, 260–   │                                    │
│   520px)            │  Nagłówek + [Refresh] [Remove]     │
│                     │                                    │
│  [Refresh]          │  ┌──────────────────────────────┐  │
│  [New invite]       │  │ Historia wiadomości          │  │
│  [Reply] (jeśli     │  │ (scroll area)                │  │
│   wybrany)          │  │                              │  │
│                     │  │ Verify emoji modal           │  │
│  Dodaj kontakt:     │  │ (jeśli peer nowy)            │  │
│  Label: [input]     │  └──────────────────────────────┘  │
│  Kod: [textarea]    │                                    │
│  [Add contact]      │  Compose:                          │
│                     │  [multiline input]                 │
│  Kontakty:          │  [Send]                            │
│  ○ Alicja           │                                    │
│  ● Bartek           │                                    │
│  ○ Celina           │                                    │
└─────────────────────┴────────────────────────────────────┘
```

**Wąskie okno (<760px):** układ pionowy — panel kontaktów nad panelem wiadomości.

### Top bar

Zawsze widoczny. Zawiera:
- Aktualny status (wynik ostatniej operacji)
- Wskaźnik ładowania (spinner gdy `busy=true`)
- `[Retry / Refresh]` — ponowny ping + odświeżenie stanu
- `[Wipe local]` — dwuetapowe potwierdzenie (pierwsze kliknięcie zmienia etykietę na `[Confirm wipe local]`)

### Panel kontaktów

- `[Refresh]` — odświeża listę kontaktów
- `[New invite]` — tworzy nowe zaproszenie (generuje kod `lci1:...`)
- `[Reply]` — odpowiada na zaproszenie dla wybranego kontaktu (uzupełnia jego klucze)
- Sekcja dodawania kontaktu z kodu zaproszenia: label + textarea na kod
- Lista kontaktów jako przyciski (zaznaczony = wybrany)

### Panel wiadomości

- Nagłówek z nazwą kontaktu i informacją czy peer jest ustawiony (`peer_set`)
- `[Refresh]` — przeładowuje historię z lokalnej bazy (wiadomości przychodzące dochodzą same przez auto-fetch w tle)
- `[Remove contact]` — usuwa kontakt
- Historia wiadomości w polu przewijalnym; każda wiadomość: `You/Peer · timestamp · id` + treść
- Pole compose (multiline) + `[Send]` (aktywny tylko gdy `peer_set=true` i tekst niepusty)

### Verify emoji modal

Automatycznie pojawia się gdy:
- `peer_set=true`
- brak wiadomości wychodzących (peer jeszcze nie odpowiedział)
- nie był jeszcze pokazany dla tego kontaktu

Wyświetla ciąg emoji do weryfikacji kanałem out-of-band (np. przez telefon). 
Przycisk `[Hide]` zamyka modal; pokazuje się tylko raz per kontakt per sesja.

---

## IPC — komunikacja z lithiumd

### Transport

- **Linux/macOS:** Unix domain socket (connect per żądanie)
- **Windows:** Named pipe

### Protokół

JSON-lines (jedno żądanie = jedna linia JSON, jedna odpowiedź = jedna linia JSON).

**Format żądania:**
```json
{
  "cmd": "nazwa_komendy",
  "id": 1,
  "auth_token": "hex_token",
  ...pola_komendy...
}
```

**Format odpowiedzi:**
```json
{
  "id": 1,
  "ok": true,
  "result": { ... },
  "error": null
}
```

### Auth token

Po odblokowaniu keystora daemon zwraca `ipc_auth_token`. Token przechowywany jest w 
`OnceLock<Mutex<Option<String>>>` i automatycznie dołączany do każdego kolejnego żądania. Wyczyszczony gdy:
- daemon odpowie `ipc_auth_failed` lub `ipc_auth_required`
- wykonano `wipe_local`

### Komendy IPC

Pełna referencja: [ipc-reference.md](ipc-reference.md). Komendy istotne dla GUI:

| Komenda                | Opis                                       | Kluczowe pola żądania              | Odpowiedź                |
|------------------------|--------------------------------------------|------------------------------------|--------------------------|
| `ping`                 | Sprawdź stan daemona                       | —                                  | `ui_state`, `status.*`   |
| `unlock_keystore`      | Odblokuj keystore hasłem                   | `data_password`                    | `ipc_auth_token`         |
| `lock_keystore`        | Zablokuj keystore (zeroizacja)             | —                                  | —                        |
| `set_credentials`      | Ustaw handler + hasło konta                | `handler`, `password`              | —                        |
| `set_server_url`       | Ustaw adres relay'a                        | `url`                              | —                        |
| `set_server_identity`  | Ustaw tożsamość serwera (hex)              | `data`                             | —                        |
| `register`             | Zarejestruj profil na serwerze             | —                                  | —                        |
| `unlock_storage`       | Inicjalizuj lokalny storage                | —                                  | —                        |
| `contacts_list`        | Pobierz listę kontaktów                    | —                                  | `contacts[]`             |
| `messages_list`        | Pobierz historię wiadomości                | `contact_id`, `limit`, `before_id` | `messages[]`, `paging`   |
| `contact_send`         | Wyślij wiadomość                           | `contact_id`, `plaintext`          | —                        |
| `create_invite`        | Parowanie krok 1: utwórz commitment        | `contact_id` (opt.)                | `contact_id`, `commitment` |
| `accept_commitment`    | Krok 2: przyjmij commitment, zwróć swój kod| `commitment`, `label`              | `contact_id`, `code`     |
| `reveal_invite`        | Krok 3: ujawnij swój kod po kodzie peera   | `contact_id`, `peer_code`, `label` | `code`                   |
| `finalize_pairing`     | Krok 4: zweryfikuj kod peera               | `contact_id`, `peer_code`          | `ok`                     |
| `contact_verify_emoji` | Pobierz emoji weryfikacyjne                | `contact_id`                       | `emojis[]`               |
| `contact_forget`       | Usuń kontakt                               | `contact_id`                       | —                        |
| `delete_account`       | Usuń konto na serwerze + lokalnie          | —                                  | —                        |
| `wipe_local`           | Wyczyść wszystkie dane lokalne             | —                                  | —                        |
| `shutdown`             | Zamknij daemona                            | —                                  | —                        |

Manual fetch nie istnieje — wiadomości przychodzące pobiera w tle daemon (cover traffic), a GUI odświeża widok przez `messages_list` z lokalnej bazy (auto-refresh co 3 s).

### Typy odpowiedzi

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
        // ... i inne flagi stanu
    },
    actions_needed: Vec<String>,
}

ContactInfo {
    contact_id: String,
    label: String,
    peer_set: bool,    // czy druga strona już zaakceptowała zaproszenie
    peer_cid: String,
}

MessageItem {
    id: i64,
    direction: String,          // "in" | "out"
    kind: String,               // "text" | ...
    text: Option<String>,
    ui: Value,                  // metadane UI (mailbox_gen, itp.)
    created_at: String,
}

CreateInviteResult     { contact_id: String, commitment: String }
AcceptCommitmentResult { contact_id: String, code: String }
RevealInviteResult     { code: String }
VerifyEmojiResult      { emojis: Vec<String> }
```

---

## Przepływ zapraszania kontaktu

Parowanie to jednostronny commit-reveal (4 komunikaty out-of-band; kolejność wymusza daemon):

```
Strona A                              Strona B
---------                             ---------
create_invite() -> commitment_A

Przekaż commitment_A Stronie B (OOB: czat, e-mail, itp.)

                                      Wklej commitment_A + label
                                      accept_commitment(commitment_A) -> kod_B

                                      Przekaż kod_B Stronie A

Wklej kod_B
reveal_invite(contact_id=A, peer_code=kod_B) -> kod_A
  (A ustawia peera na tożsamość B)

Przekaż kod_A Stronie B

                                      Wklej kod_A
                                      finalize_pairing(contact_id=B, peer_code=kod_A)
                                      (B weryfikuje kod_A względem commitment_A)

Teraz obie strony mają peer_set=true -> można wysyłać wiadomości
```

---

## Szczegóły implementacyjne

### Czcionka emoji (Linux)

Przy starcie aplikacja szuka czcionki emoji w systemowych lokalizacjach:
```
/usr/share/fonts/truetype/noto/NotoEmoji-Regular.ttf
/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf
/usr/share/fonts/truetype/ancient-scripts/Symbola_hint.ttf
/usr/share/fonts/TTF/Symbola.ttf
```
Jeśli nie znaleziona, emoji wyświetlają się jako kwadraty.

### Blokowanie UI (`busy`)

Flaga `busy=true` ustawiana przy każdym wysłaniu komendy; resetowana gdy `drain_events()` odbierze odpowiedź. Wszystkie przyciski są wyłączone gdy `busy=true`.

### Auto-selekcja kontaktu

Po załadowaniu listy kontaktów:
- Jeśli żaden nie był wybrany → automatycznie zaznaczany pierwszy
- Jeśli wybrany kontakt zniknął (np. po `forget`) → selekcja przesuwa się na pierwszy dostępny
- Po `create_invite` / `accept_commitment` → automatycznie zaznaczany nowy kontakt

### Paginacja wiadomości

`messages_list` przyjmuje `limit` i `before_id` (do stronicowania). Obecna implementacja GUI ładuje ostatnie 100 wiadomości (`limit=100`, `before_id=None`).