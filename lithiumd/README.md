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

Daemon wymaga kilku zmiennych środowiskowych zawierających publiczne klucze serwera:

```bash
export SERVER_X25519=<hex 32 bajtów>
export SERVER_KYBER=<hex 1568 bajtów>
export SERVER_ED25519=<hex 32 bajtów>
export SERVER_DILITHIUM=<hex 2592 bajtów>
export LITHIUMD_BASE_URL=https://relay.example.com
export LITHIUMD_DATA_DIR=/home/user/.local/share/lithiumd   # opcjonalnie
```

Domyślny katalog danych: `~/.local/share/lithiumd/`.
Socket IPC: `{data_dir}/lithiumd.sock` (Linux/macOS) lub `\\.\pipe\lithiumd` (Windows).

---

## IPC — protokół komunikacji

Daemon nasłuchuje połączeń na:
- **Unix socket** (Linux/macOS) — uprawnienia `0o600`, tylko owner
- **Windows named pipe** — `reject_remote_clients(true)`, tylko lokalne połączenia

Protokół: **JSON-lines** (jedna komenda = jedna linia JSON, jedna odpowiedź = jedna linia JSON).

### Format żądania

```json
{
    "id": 1,
    "auth_token": "hex_token",
    "cmd": "command_name",
    ...pola_komendy...
}
```

### Format odpowiedzi

```json
{
    "id": 1,
    "ok": true,
    "result": { ... },
    "error": null
}
```

### Autoryzacja IPC

Tylko `Ping` i `UnlockKeystore` działają bez tokenu. Wszystkie pozostałe komendy wymagają `auth_token` w żądaniu.

Token sesji jest emitowany po pomyślnym `UnlockKeystore` jako pole `ipc_auth_token` w odpowiedzi. 
Token = hex-encoded 32 losowe bajty.

Na **Linuxie** token jest dodatkowo wiązany z UID i PID klienta 
(odczytanym przez `SO_PEERCRED`). Żądania z innego PID lub UID zostaną odrzucone błędem `ipc_auth_failed`.

Idle timeout połączenia: **300 sekund**. Maksymalna liczba równoległych połączeń: **1**.

---

## Komendy IPC

### `Ping` — bez autoryzacji

Zwraca aktualny stan daemona.

```json
{ "cmd": "ping" }
```

Odpowiedź zawiera flagi: `keystore_locked`, `needs_register`, `storage_locked`, `needs_credentials`.

---

### `UnlockKeystore` — bez autoryzacji

Odblokowuje lokalny keystore hasłem danych (`data_password`).
Jest to pierwszy krok — bez tego żadna inna komenda (poza `Ping`) nie zadziała.

```json
{ "cmd": "unlock_keystore", "data_password": "..." }
```

Kroki:
1. Walidacja `data_password` przez `PasswordPolicy` (min 8 znaków, wielkie/małe/cyfry/znaki specjalne, bez spacji).
2. Jeśli keystore jest już odblokowany — porównuje hasło z bieżącym i zwraca `ok` lub błąd.
3. Sprawdza, że `data_password` różni się od `account_password` (jeśli był już ustawiony).
4. Inicjalizuje `PasswordFileMkProvider` z plikiem `{data_dir}/keystore/user/default/mk.enc`.
5. Uruchamia `KeyManager` w `{data_dir}/keystore/`.
6. Spawnuje `MkRotator` — background task sprawdzający rotację MK co **30 sekund**.
7. Tworzy `EphemeralStoreManager` i `ProtocolManager`.
8. Jeśli `account_creds` były już ustawione — przekazuje je do `ProtocolManager`.

Odpowiedź:
```json
{ "unlocked": true, "ipc_auth_token": "<64 hex znaków>" }
```

---

### `SetCredentials` — wymaga auth

Ustawia handler i hasło konta na serwerze.

```json
{
    "cmd": "set_credentials",
    "handler": "alice",
    "password": "AccountP@ssword123"
}
```

- `handler` i `password` przechodzą walidację `PasswordPolicy`.
- Hasło konta musi różnić się od `data_password`.
- Dane są przechowywane w `state.account_creds` (w pamięci, `SecretString`, zeroizowane przy lock).
- Jeśli `ProtocolManager` jest aktywny — credentials są do niego przekazane natychmiast.

---

### `Register` — wymaga auth

Rejestruje konto na serwerze. Wywołuje się **raz** na nowym urządzeniu.

```json
{ "cmd": "register" }
```

Wymaga: keystore odblokowany + credentials ustawione + `needs_register == true`.

Kroki:
1. Generuje losowy DEK (32 bajty) — klucz szyfrowania danych lokalnych.
2. Szyfruje DEK hasłem konta (`wrap_dek_for_server_hex`): `Argon2id(account_password, random_salt)` + AES-256-GCM-SIV.
3. Wysyła POST `/user/register` z `{ handler, password, dek: encrypted_dek_hex }`.
4. Ustawia `server_dek` w `PasswordFileMkProvider` (potrzebny do wyprowadzania sekretów DB).
5. Czyści flagę `needs_register`, tworzy marker `registered.flag`.

---

### `UnlockStorage` — wymaga auth

Pobiera DEK z serwera i inicjalizuje lokalną bazę SQLite.

```json
{ "cmd": "unlock_storage" }
```

Wymaga: keystore odblokowany + zarejestrowany.

Kroki:
1. Wywołuje `ProtocolManager::get_dek()` — wykonuje shake + login jeśli sesja wygasła, pobiera zaszyfrowany DEK z serwera.
2. Deszyfruje DEK: `unwrap_dek_from_server_hex(dek_hex, data_password)`.
3. Ustawia `server_dek` w `PasswordFileMkProvider`.
4. Inicjalizuje `DataManager` z SQLite (`{data_dir}/data/lithiumd.db`).

Po `UnlockStorage` dostępne są komendy kontaktowe i wiadomości.

---

### `CreateInvite` — wymaga auth + storage

Tworzy kod zaproszenia dla nowego lub istniejącego kontaktu.

```json
{
    "cmd": "create_invite",
    "contact_id": null,
    "server": "https://relay.example.com"
}
```

**Nowy kontakt** (`contact_id == null`): Generuje nowy `contact_id` (32 losowe bajty) i cały
zestaw kluczy per-kontakt (X25519, ML-KEM-1024, Ed25519, ML-DSA-87 + 3 mailbox keypairs). 
Zapisuje stan w DB i zwraca kod zaproszenia.

**Istniejący kontakt**: Odczytuje stan z DB i koduje istniejące klucze publiczne.

Odpowiedź zawiera `contact_id` (hex) i `invite_code` (string `lci1:HEXDATA`).

---

### `AcceptInvite` — wymaga auth + storage

Przyjmuje kod zaproszenia od drugiej strony.

```json
{
    "cmd": "accept_invite",
    "code": "lci1:...",
    "contact_id": null,
    "label": "Alice"
}
```

**Bez `contact_id`** (nowe parowanie obustronne): Dekoduje kod zaproszenia, generuje własny `contact_id` i klucze,
zapisuje peer info, zwraca `contact_id` + `my_code` (do odesłania drugiej stronie).

**Z `contact_id`** (przyjęcie od istniejącego kontaktu): Ładuje kontakt z DB, aktualizuje `peer_state` danymi 
z kodu zaproszenia. `my_code` w odpowiedzi jest pusty — wymiana jest jednostronna.

---

### `ContactsList` — wymaga auth + storage

Zwraca listę kontaktów z ich statusami.

```json
{ "cmd": "contacts_list" }
```

---

### `ContactSend` — wymaga auth + storage

Szyfruje i wysyła wiadomość do kontaktu.

```json
{
    "cmd": "contact_send",
    "contact_id": "<hex>",
    "plaintext": "Treść wiadomości"
}
```

Kroki:
1. Ładuje `self_state` i `peer_state` kontaktu z DB (deszyfruje AES-256-GCM-SIV).
2. `ensure_self_keyring` — inicjalizuje `e2e_tx`, `e2e_rx`, `bootstrap` jeśli brakuje.
3. `ensure_mailbox_state` — inicjalizuje stan mailbox.
4. Generuje prekeys jeśli `prekeys_should_advertise`.
5. Określa tryb: `bootstrap` (pierwsze wysłanie) / `ratchet` (po wymianie kluczy) / `prekey_recover` (recovery).
6. Szyfruje wiadomość (`encrypt_for_peer`) → `WireV1`.
7. Wstawia `{mailbox, content}` do kolejki send dispatchera (`traffic.rs`) — emisja `MsgSend` jedzie
   później w slocie stałej kadencji, nie synchronicznie. Cała funkcja działa pod `contact_fetch_locks`.
8. Zapisuje wiadomość w DB (kierunek=outbound).
9. Aktualizuje `self_state` i `peer_state` w DB.

---

### Pobieranie wiadomości — automatyczne (brak komendy IPC)

Manual fetch został usunięty. Wiadomości przychodzące pobiera w tle stałokadencyjny fetch
dispatcher w `traffic.rs` (jeden `MsgFetch` na tick, round-robin po skrzynkach inbound wszystkich
kontaktów plus cover-skrzynka). Logika per-skrzynka jest ta sama co dawniej:

1. Generacje mailbox do sprawdzenia: `past 2 + current + future 1`.
2. Dla każdej: wyprowadza adres mailbox (ECDH + HKDF), pobiera przez `ProtocolManager::send(MsgFetch, ...)`.
3. Dla każdej wiadomości `decrypt_for_us` (ratchet/bootstrap), przy `to_id_unknown` próbuje `decrypt_for_prekey` (prekey recovery).
4. Zapisuje odszyfrowane wiadomości w DB (kierunek=inbound, dedup po `msg_id`).
5. Aktualizuje stany w DB, pod `contact_fetch_locks` (serializacja z `contact_send`).

GUI odczytuje lokalny store przez `MessagesList` (poll co kilka sekund).

---

### `MessagesList` — wymaga auth + storage

Zwraca stronę wiadomości z danym kontaktem (paginacja).

```json
{
    "cmd": "messages_list",
    "contact_id": "<hex>",
    "limit": 50,
    "before_id": null
}
```

`limit` jest clampowany do zakresu 1–200. Wewnętrznie pobiera `limit + 1` rekordów (do wykrycia `has_more`). 
Wyniki są zwracane w kolejności chronologicznej.

---

### `ContactVerifyEmoji` — wymaga auth + storage

Generuje 6 emoji do weryfikacji tożsamości out-of-band.

```json
{ "cmd": "contact_verify_emoji", "contact_id": "<hex>" }
```

Kroki:
1. ECDH(`self_x_priv`, `peer_x_pub`) → shared secret.
2. HKDF(shared_secret, salt=`sorted(cid_a || cid_b)`, info=`"lithiumd/verify-emoji/v1"`) → 6 bajtów.
3. Każdy bajt mod 64 → indeks w tablicy 64 unikalnych emoji.

Obie strony muszą zobaczyć identyczne 6 emoji — weryfikacja jest czysto lokalna, nie wymaga komunikacji z serwerem.

---

### `ContactForget` — wymaga auth + storage

Usuwa kontakt i wszystkie jego wiadomości oraz prekeys z lokalnej bazy.

```json
{ "cmd": "contact_forget", "contact_id": "<hex>" }
```

Operacja jest nieodwracalna.

---

### `Shutdown` — wymaga auth

Wysyła sygnał zamknięcia do głównej pętli daemona.

```json
{ "cmd": "shutdown" }
```

---

### `WipeLocal` — wymaga auth

Usuwa całe `{data_dir}` z nadpisaniem i fsync.

```json
{ "cmd": "wipe_local" }
```

Sekwencja: overwrite zerami (chunki 1 MB) + `fsync()` na każdym pliku + `fsync()` na katalogu (Unix) + `remove_dir_all`.
Następnie zamknięcie daemona.

---

## Stan daemona — `DaemonState`

```rust
pub struct DaemonState {
    // Aktywne komponenty (None = zablokowane)
    proto:        Arc<Mutex<Option<Arc<ProtocolManager<PasswordFileMkProvider>>>>>,
    mk_rotator:   Arc<Mutex<Option<MkRotator>>>,
    keys:         Arc<Mutex<Option<Arc<Mutex<KeyManager<PasswordFileMkProvider>>>>>>,
    local_db:     Arc<Mutex<Option<Arc<DataManager<PasswordFileMkProvider>>>>>,

    // Dane wrażliwe (zeroizowane przy lock)
    data_pass:    Arc<Mutex<Option<SecretString>>>,   // data_password
    account_creds: Arc<Mutex<Option<(SecretString, SecretString)>>>,  // (handler, password)
    dek_plain:    Arc<Mutex<Option<Byte32>>>,          // odszyfrowany DEK

    // Flagi
    needs_register: Arc<Mutex<bool>>,

    // Autoryzacja IPC
    ipc_auth:    Arc<Mutex<IpcAuthState>>,

    // Blokady fetch per kontakt
    contact_fetch_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,

    // Konfiguracja
    base_dir:    PathBuf,
    base_url:    Url,
    bootstrap:   ServerBootstrap,
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
password_root   = Argon2id(data_password, salt="lithium/user-provider/root/v1")
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

| Endpoint   | Ścieżka          | Session | JWT     | Podpisanie         |
|------------|------------------|---------|---------|--------------------|
| `Shake`    | `/shake`         | nie     | nie     | efemeryczne klucze |
| `Register` | `/user/register` | tak     | nie     | klucze tożsamości  |
| `Login`    | `/user/login`    | tak     | nie     | klucze tożsamości  |
| `MsgSend`  | `/msg/send`      | tak     | **tak** | klucze tożsamości  |
| `MsgFetch` | `/msg/fetch`     | tak     | nie     | efemeryczne klucze |

### Padding żądań

Body i headery są paddowane przed szyfrowaniem, żeby rozmiar payload nie zdradzał zawartości:
- **Body**: `data || 0x80 || 0x00...` do wielokrotności losowego bloku 32–64 KB.
- **Headery**: paddowane do wielokrotności losowego bloku 4–8 KB.

### Weryfikacja odpowiedzi serwera

Każda odpowiedź jest weryfikowana dwiema sygnaturami (Ed25519 + ML-DSA-87) względem kluczy załadowanych 
z env (`SERVER_ED25519`, `SERVER_DILITHIUM`). Oba algorytmy muszą przejść weryfikację.

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

Lokalna baza w `{data_dir}/data/lithiumd.db`. Tryb WAL, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000ms`.

### Schemat

**`contacts`**

| Kolumna          | Typ         | Opis                                                       |
|------------------|-------------|------------------------------------------------------------|
| `id`             | i64 PK      | —                                                          |
| `contact_id`     | BLOB UNIQUE | 32 bajty, identyfikator kontaktu                           |
| `server`         | TEXT        | URL relay'a                                                |
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

Rotacja jest crash-safe (szczegóły w `lithium_core/README.md`). Po rotacji MK:
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
[VER: 1 bajt = 3]
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

Łączna wielkość danych binarnych: **4363 bajty** → ~**8726 znaków hex** po `lci1:`.

---

## Struktura katalogów danych

```
{data_dir}/
├── keystore/
│   └── user/
│       └── default/
│           ├── mk.enc          ← Master Key zaszyfrowany hasłem
│           ├── pub/            ← Klucze publiczne (cache)
│           ├── priv/           ← Klucze prywatne (*.keyf, wrapped MK)
│           ├── secrets/        ← Sekrety pochodne (*.keyf, wrapped MK)
│           └── .rotate/        ← Tymczasowy katalog rotacji MK
├── data/
│   └── lithiumd.db            ← SQLite (wiadomości, kontakty, prekeys)
├── registered.flag            ← Marker rejestracji (uprawnienia 0o600)
└── lithiumd.sock              ← Unix socket IPC (Linux/macOS)
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
w tym plaintextu i kluczy. Binding tokenu do UID/PID (Linux) ogranicza ryzyko — patrz `lithium_assumptions.md`.