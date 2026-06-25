# lithiumd

Lokalny daemon kryptograficzny Lithium. Działa na maszynie użytkownika i jest jedynym komponentem,
który ma dostęp do kluczy prywatnych i plaintextu wiadomości. Serwer (`lithiums`) nigdy 
nie widzi niezaszyfrowanych danych — daemon pośredniczy między GUI a serwerem, 
wykonując wszystkie operacje kryptograficzne lokalnie.

## Miejsce w architekturze

```
lithiumg (GUI)
  ↕ JSON-lines / Unix socket lub Windows named pipe
lithiumd (daemon)   ← ten crate
  ↕ HTTPS + Kyberbox (X25519 + ML-KEM-1024)
lithiums (serwer relay)
```

## Uruchomienie

Klucze publiczne serwera **nie** są konfigurowane przez zmienne środowiskowe — daemon wczytuje je z pliku `server.identity` (domyślnie `{data_dir}/server.identity`, override `LITHIUMD_SERVER_IDENTITY`). Adres relay'a i tożsamość serwera ustawia się w runtime komendami IPC `set_server_url` i `set_server_identity`; plik tożsamości jest wgrywany kanałem out-of-band (patrz [security-model.md](../security/security-model.md)).

```bash
export LITHIUMD_DATA_DIR=/home/user/.local/share/lithiumd   # opcjonalnie
```

Domyślny katalog danych (Linux): `{XDG_DATA_HOME}/lithiumd` lub `~/.local/share/lithiumd/`.
Socket IPC: `{XDG_RUNTIME_DIR}/lithiumd.sock` (Linux/macOS, override `LITHIUMD_SOCKET_PATH`) lub `\\.\pipe\lithiumd` (Windows).

---

## IPC

Daemon wystawia gniazdo IPC (Unix socket / named pipe na Windows, protokół JSON-lines). Pełny kontrakt — żądania, odpowiedzi, kody błędów, maszyna stanów, polityka tokenu — jest w [ipc-reference.md](../protocol/ipc-reference.md); cykl życia endpointu i polityka połączeń (idle timeout, limit połączeń, `LITHIUMD_IPC_ALLOWED_UID`) w [daemon-runtime.md](../operations/daemon-runtime.md).

Istotne z perspektywy daemona: token sesji emitowany przy `unlock_keystore` jest na Linuxie wiązany z UID+PID nadawcy (`SO_PEERCRED`, porównanie stałoczasowe) i unieważniany przez `lock_keystore`/`wipe_local`. IPC jest granicą zaufania procesu — patrz „Model bezpieczeństwa".

Wewnętrzną obsługę poszczególnych komend opisują sekcje architektury poniżej: stan i jego wymazywanie („Stan daemona"), wysyłka i odbiór („System E2E", „System mailbox"), dostęp do serwera („ProtocolManager"), rotacja MK i baza SQLite.

## Stan daemona — `DaemonState`

```rust
pub struct DaemonState {
    // Aktywne komponenty (None = zablokowane)
    proto:        Arc<Mutex<Option<Arc<ProtocolManager<PasswordFileMkProvider>>>>>,
    mk_rotator:   Arc<Mutex<Option<MkRotator>>>,
    traffic:      Arc<Mutex<Option<Traffic>>>,                        // dispatcher cover traffic
    send_tx:      Arc<Mutex<Option<mpsc::Sender<PendingSend>>>>,      // kolejka send dispatchera
    keys:         Arc<Mutex<Option<SharedKeyManager>>>,
    local_db:     Arc<Mutex<Option<Arc<DataManager<PasswordFileMkProvider>>>>>,

    // Dane wrażliwe (zeroizowane przy lock)
    data_pass:    Arc<Mutex<Option<SecretString>>>,                   // data_password
    account_creds: Arc<Mutex<Option<(SecretString, SecretString)>>>,  // (handler, password)
    dek_plain:    Arc<Mutex<Option<Byte32>>>,                         // odszyfrowany DEK

    // Flagi
    needs_register:    Arc<Mutex<bool>>,
    mk_rotation_error: Arc<Mutex<bool>>,                             // ostatnia rotacja MK zawiodła

    // Autoryzacja IPC
    ipc_auth:    Arc<Mutex<IpcAuthState>>,

    // Blokady fetch per kontakt
    contact_fetch_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,

    // Konfiguracja
    base_dir:      PathBuf,
    base_url:      Arc<RwLock<Option<Url>>>,
    identity_path: PathBuf,
}
```

`lock_keystore()` wymazuje z pamięci: `dek_plain`, `data_pass`, `account_creds`, `proto`, `local_db`, 
`keys`, `ipc_auth.session_token`. Zatrzymuje też `MkRotator`.

---

## `PasswordFileMkProvider`

Implementacja `MkProvider` specyficzna dla lithiumd. Łączy hasło danych z komponentem serwerowym, 
żeby odzyskanie lokalnego dysku bez serwera nie wystarczyło do odszyfrowania kluczy.

### Format pliku MK (`mk.enc`)

```
[LMK1: 4 bajty magic]
[salt_len: 1 bajt = 32]
[salt: 32 bajty]
[blob_len: 4 bajty LE]
[blob: AES-256-GCM-SIV(MK, key=Argon2id(password, salt), aad="lithium/mkfile/v1")]
```

### Derywacja klucza do odczytu MK

```
user_key = Argon2id(data_password, salt)   // 64 MB, 3 iteracje, 1 wątek
MK = AES-256-GCM-SIV_decrypt(blob, user_key)
```

### Derywacja sekretów (np. DEK bazy danych)

`PasswordFileMkProvider::derive_secret32` **ignoruje** `mk` z `KeyManager` i zamiast tego używa:

```
password_root   = Argon2id(data_password, salt=root.salt)   // losowa per-instalacja sól z pliku root.salt
combined_root   = HKDF(input=server_dek, salt=password_root, info="lithium/user-provider/combined/v1")
secret          = HKDF(combined_root, info=label)
```

**Konsekwencja**: Bez `server_dek` (pobranego z serwera przez `UnlockStorage`) nie da się wyprowadzić 
sekretów DB, nawet mając hasło i lokalny dysk. Jest to celowa właściwość modelu bezpieczeństwa.

---

## `ProtocolManager` — transport do serwera

Zarządza całą komunikacją HTTP z serwerem. Każde żądanie jest szyfrowane Kyberbox 
(X25519 + ML-KEM-1024) i dual-podpisane (Ed25519 + ML-DSA-87).

### Stan sesji w `EphemeralStoreManager`

| Klucz                  | Zawartość                                         | TTL    |
|------------------------|---------------------------------------------------|--------|
| `proto/server/ses_x`   | Session X25519 hex (od serwera)                   | 120 s  |
| `proto/server/ses_k`   | Session ML-KEM hex (od serwera)                   | 120 s  |
| `proto/server/peer_x`  | Ephemeral X25519 serwera (z ostatniej odpowiedzi) | 120 s  |
| `proto/server/peer_k`  | Ephemeral ML-KEM serwera (z ostatniej odpowiedzi) | 120 s  |
| `proto/server/jwt`     | JWT token                                         | 120 s  |
| `proto/server/dek_enc` | Zaszyfrowany DEK (hex)                            | 3600 s |

### Endpoints i ich właściwości

| Endpoint         | Ścieżka                 | Session | JWT     | Klucze w nagłówkach          |
|------------------|-------------------------|---------|---------|------------------------------|
| `Shake`          | `/shake`                | nie     | nie     | efemeryczne                  |
| `RegisterStart`  | `/user/register/start`  | tak     | nie     | tożsamości                   |
| `RegisterFinish` | `/user/register/finish` | tak     | nie     | tożsamości                   |
| `LoginStart`     | `/user/login/start`     | tak     | nie     | brak (weryfik. po `handler`) |
| `LoginFinish`    | `/user/login/finish`    | tak     | nie     | brak (weryfik. po `handler`) |
| `Revoke`         | `/user/revoke`          | tak     | nie     | efemeryczne                  |
| `Delete`         | `/user/delete`          | tak     | **tak** | brak (tożsamość z JWT)       |
| `MsgSend`        | `/msg/send`             | tak     | nie     | efemeryczne (+ PoW)          |
| `MsgFetch`       | `/msg/fetch`            | tak     | nie     | efemeryczne                  |

### Padding żądań

Body i headery są paddowane przed szyfrowaniem, żeby rozmiar payload nie zdradzał zawartości:
- **Body**: `data || 0x80 || 0x00...` do wielokrotności losowego bloku 32–64 KB.
- **Headery**: paddowane do wielokrotności losowego bloku 4–8 KB.

### Weryfikacja odpowiedzi serwera

Każda odpowiedź jest weryfikowana dwiema sygnaturami (Ed25519 + ML-DSA-87) względem kluczy publicznych
serwera załadowanych z pliku `server.identity`. Oba algorytmy muszą przejść weryfikację.

### Rotacja kluczy sesji

Po każdej odpowiedzi serwer może odesłać nowe `ses-x` i `ses-k` w nagłówkach odpowiedzi. 
Są one automatycznie aktualizowane w ephemeral store.

---

## System E2E — szyfrowanie end-to-end

Szyfrowanie E2E działa niezależnie od szyfrowania transportu. Nawet jeśli transport zostałby
skompromitowany, wiadomości pozostają zaszyfrowane kluczami per-kontakt.

### Format `WireV1` (binarny format wiadomości)

```
[LM1: 3 bajty magic]
[VER: 1 bajt = 1]
[to_id: 32 bajty]           ← identyfikator klucza odbiorczego
[from_x_pub: 32 bajty]      ← efemeryczny X25519 nadawcy
[seed_len: 2 bajty BE]
[seed: seed_len bajtów]     ← ML-KEM ciphertext + zaszyfrowany seed
[hdr_len: 4 bajty BE]
[enc_headers: hdr_len bajtów]
[body_len: 4 bajty BE]
[enc_body: body_len bajtów]
```

`to_id` = `HKDF(x_pub_bytes || k_pub_bytes, info="lithiumd/e2e-peer-kid/v1")` — identyfikator pary kluczy odbiorczych adresata.

### Tryby szyfrowania

**`bootstrap`** — pierwsza wiadomość do kontaktu:
- Celuje w klucze bootstrapowe z zaproszenia (`x_pub`, `k_pub`).
- Nadawca nie ma jeszcze kluczy odpowiedzi od peera.

**`ratchet`** — po odebraniu pierwszej wiadomości zwrotnej:
- Celuje w klucze `reply` z ostatnio odebranej wiadomości (`e2e_peer.id`, `e2e_peer.x_pub`, `e2e_peer.k_pub`).
- Klucze odpowiedzi są rotowane przy każdej odebranej wiadomości.

**`prekey_recover`** — odzysk po desynchronizacji stanu:
- Celuje w prekey opublikowany przez peera (`prekeys_remote`).
- Pozwala wznowić komunikację bez nowej wymiany zaproszeń.

### Podpisywanie wiadomości E2E

Każda wiadomość jest dual-podpisana kluczami tożsamości kontaktu (Ed25519 + ML-DSA-87):

```
sig_input = "lithiumd/e2e-msg-sig/v1" || to_id || from_x_pub
            || u32(len(hdr_unsigned)) || hdr_unsigned
            || u32(len(body)) || body
```

`hdr_unsigned` to JSON nagłówka **bez** pól `auth`. Sygnatury są wbudowane w zaszyfrowany nagłówek (`enc_headers`),
więc serwer ich nie widzi.

### Klucze odbiorcze (RX keyring)

Przy każdym wysłaniu nadawca generuje nową parę RX (X25519 + ML-KEM-1024) i wysyła publiczną część w
nagłówku (`reply`). Peer szyfruje kolejną wiadomość do tych kluczy.

Klucze RX są przechowywane w `self_state["e2e_rx"]["keys"]` z numerem sekwencji (`seq`). 
GC usuwa klucze starsze niż `window=32` sekwencji od ostatniego potwierdzenia (`ack_seq`).

Klucze bootstrapowe są usuwane z `self_state` (bezpieczna kasacja przez `SecretJson::drop`) 
po spełnieniu obu warunków: peer potwierdził odbiór (`ack_seq > 0` lub `retire_ok`) i peer ma ustawiony `e2e_peer`.

### Prekeys

Przy pierwszym wysłaniu daemon generuje zestaw prekeys (domyślnie 5) i załącza ich publiczne 
części do nagłówka wiadomości. Peer zapisuje je w `peer_state["prekeys_remote"]`.
W trybie `prekey_recover` peer sięga po prekey do zaszyfrowania wiadomości odzysku.

Prywatne części prekeys są przechowywane w tabeli `prekeys` w SQLite (zaszyfrowane DEK-iem, AAD=`lithiumd/prekey/v1`).
Prekey jest usuwany po użyciu (`take_prekey`).

---

## System mailbox

Mailbox jest adresem skrzynki na serwerze, z której odbiorca pobiera wiadomości. Adres jest wyprowadzany
kryptograficznie — serwer nie wie, kto do kogo pisze.

### Derywacja adresu mailbox

```
shared = ECDH(sender_out_priv, receiver_in_pub)
salt   = sender_cid || receiver_cid || generation (8 bajtów BE)
address = HKDF(shared, salt=salt, info="lithium/mbox/address/v1")  → 32 bajty
```

Nadawca i odbiorca obliczają adres niezależnie, bez komunikacji. Serwer widzi tylko adres jako opaque 32-bajtowy identyfikator.

### Klucze mailbox

Każdy kontakt ma w `self_state`:
- `mbox_in_priv`/`mbox_in_pub` — stabilny klucz odbiorczy (niezmienny, do odbierania od danego peera).
- `mbox_out_cur_priv`/`mbox_out_cur_pub` — bieżący klucz nadawczy.
- `mbox_out_next_priv`/`mbox_out_next_pub` — następny klucz nadawczy (przygotowany z wyprzedzeniem).

### Rotacja klucza nadawczego

Po wysłaniu `rotate_every` (domyślnie 32) wiadomości: `cur ← next`, generuje nowe `next`.
Wiadomości informują peera o bieżących i następnych kluczach publicznych (`header["mailbox"]["sender_cur_x_pub"]`, `sender_next_x_pub"`).

### Fetch

Auto-fetch (`traffic.rs`) sprawdza generacje: `peer_tx_gen_seen - 2` do `peer_tx_gen_seen + 1` — łącznie do 4 generacji.
Gwarantuje odbiór wiadomości mimo przeskoczenia generacji.

---

## Baza danych SQLite

Lokalna baza w `{data_dir}/storage/lithiumd.sqlite`. Tryb WAL, `synchronous=NORMAL`, `foreign_keys=ON`, `temp_store=MEMORY`, `busy_timeout=5000ms`.

### Schemat

**`contacts`**

| Kolumna          | Typ         | Opis                                                       |
|------------------|-------------|------------------------------------------------------------|
| `id`             | i64 PK      | —                                                          |
| `contact_id`     | BLOB UNIQUE | 32 bajty, identyfikator kontaktu                           |
| `peer_state_enc` | BLOB        | Zaszyfrowany stan peera (AAD: `lithiumd/contact-peer/v1`)  |
| `self_state_enc` | BLOB        | Zaszyfrowany stan własny (AAD: `lithiumd/contact-self/v1`) |
| `created_at`     | TIMESTAMP   | —                                                          |
| `updated_at`     | TIMESTAMP   | —                                                          |

**`messages`**

| Kolumna       | Typ       | Opis                                            |
|---------------|-----------|-------------------------------------------------|
| `id`          | i64 PK    | —                                               |
| `contact_id`  | BLOB      | FK do contacts                                  |
| `mailbox`     | BLOB      | Adres mailbox, z którego pobrano                |
| `direction`   | i32       | 0 = inbound, 1 = outbound                       |
| `content_enc` | BLOB      | Zaszyfrowana treść (AAD: `lithiumd/message/v1`) |
| `msg_id`      | BLOB UNIQUE | Identyfikator wiadomości do deduplikacji (NULL = brak) |
| `created_at`  | TIMESTAMP | —                                               |

**`prekeys`**

| Kolumna      | Typ         | Opis                                                     |
|--------------|-------------|----------------------------------------------------------|
| `id`         | i64 PK      | —                                                        |
| `contact_id` | BLOB        | FK do contacts                                           |
| `prekey_id`  | BLOB UNIQUE | Identyfikator prekey                                     |
| `key_enc`    | BLOB        | Zaszyfrowany materiał prekey (AAD: `lithiumd/prekey/v1`) |
| `created_at` | TIMESTAMP   | —                                                        |
| `expires_at` | TIMESTAMP   | —                                                        |
| `used_at`    | TIMESTAMP   | NULL = nieużyty                                          |

Wszystkie `*_enc` blobs są szyfrowane AES-256-GCM-SIV przez `DataManager::encrypt_db_blob`. 
DEK bazy = `derive_secret32(b"lithium/db-dek/v1")` — wyprowadzany z `combined_root` (hasło + server DEK).

---

## Rotacja Master Key

`MkRotator` to background task spawnowany przez `UnlockKeystore`. Co **30 sekund** wywołuje `KeyManager::maybe_rotate_mk()`,
które zgodnie z logiką `lithium_core` rotuje MK co **3600 sekund** (1 godzina).

Rotacja jest crash-safe (szczegóły w [lithium_core.md](lithium_core.md)). Po rotacji MK:
- Wszystkie pliki `.keyf` kluczy asymetrycznych i sekretów są re-wrapped nowym MK.
- JWT secret jest regenerowany.
- DEK bazy **nie zmienia wartości** — rewrapping dotyczy tylko pliku klucza, nie zaszyfrowanych danych w SQLite.

`MkRotator` jest zatrzymywany synchronicznie przy `lock_keystore()` — `stop_tx.send(true)` + `.await` na `JoinHandle`.

---

## Format kodu zaproszenia

```
lci1:<HEX>
```

Zawartość binarna (hex-encoded):

```
[LCI1: 4 bajty magic]
[VER: 1 bajt = 1]
[contact_id: 32 bajty]
[x_pub: 32 bajty]              ← X25519 (E2E)
[k_pub_len: 2 bajty BE = 1568]
[k_pub: 1568 bajtów]           ← ML-KEM-1024 (E2E)
[ed_pub: 32 bajty]             ← Ed25519 (podpisy)
[dili_pub_len: 2 bajty BE = 2592]
[dili_pub: 2592 bajtów]        ← ML-DSA-87 (podpisy)
[mbox_in_pub: 32 bajty]        ← Stabilny klucz odbiorczy mailbox
[mbox_out_cur_pub: 32 bajty]   ← Bieżący klucz nadawczy mailbox
[mbox_out_next_pub: 32 bajty]  ← Następny klucz nadawczy mailbox
```

Łączna wielkość danych binarnych: **4361 bajtów** → **8722 znaki hex** po `lci1:`.

---

## Struktura katalogów danych

```
{data_dir}/                      (0o700)
├── keystore/
│   ├── user/
│   │   ├── mk.enc              Master Key opakowany hasłem danych
│   │   └── root.salt           losowa per-instalacja sól Argon2 (DEK)
│   ├── pub/                    Klucze publiczne (cache)
│   ├── priv/                   Klucze prywatne (*.keyf, opakowane MK)
│   ├── secrets/                Sekrety pochodne (*.keyf, opakowane MK)
│   └── .rotate/                Tymczasowy katalog rotacji MK
├── storage/
│   └── lithiumd.sqlite         SQLite (kontakty, wiadomości, prekeys)
├── server.identity            Klucze publiczne serwera (lub LITHIUMD_SERVER_IDENTITY)
├── server_url                 Adres relay'a (tekst)
└── registered.flag            Marker rejestracji (0o600)

Socket IPC nie leży w katalogu danych — domyślnie {XDG_RUNTIME_DIR}/lithiumd.sock.
```

---

## Model bezpieczeństwa

**Zasada dwóch czynników dla sekretów DB:** Dane lokalne można odszyfrować tylko gdy jednocześnie 
dostępne są `data_password` (hasło użytkownika) i `server_dek` (komponent serwerowy). 
Utrata kontroli nad urządzeniem bez znajomości hasła lub utrata dostępu do serwera = utrata możliwości odczytu danych.
Jest to celowe.

**Izolacja per-kontakt:** Każdy kontakt ma niezależny zestaw kluczy 
(`contact_id`, X25519, ML-KEM, Ed25519, ML-DSA-87, klucze mailbox).
Kompromitacja jednego kontaktu nie kompromituje pozostałych.

**Serwer nie uczestniczy w kryptografii E2E:** Serwer widzi wyłącznie zaszyfrowane payload'y i adresy mailbox.
Nie może odszyfrować treści, nie może podrobić tożsamości peera, nie może korelować kto do kogo pisze 
(adresy mailbox są pseudolosowe).

**GC wrażliwego materiału:** Bootstrap private keys są bezpiecznie kasowane (`SecretJson::drop` z zeroizacją) gdy 
tylko peer potwierdził komunikację. Stare klucze RX są kasowane po przekroczeniu okna (32).

**IPC jako granica uprzywilejowana:** Naruszenie IPC daje dostęp do wszystkich operacji kryptograficznych daemona, 
w tym plaintextu i kluczy. Binding tokenu do UID/PID (Linux) ogranicza ryzyko — patrz [security-model.md](../security/security-model.md).