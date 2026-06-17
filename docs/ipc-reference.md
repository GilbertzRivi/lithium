# Referencja IPC daemona Lithium

Daemon `lithiumd` wystawia lokalny endpoint IPC umożliwiający GUI (lub innemu klientowi) sterowanie wszystkimi operacjami kryptograficznymi. Klucze prywatne istnieją wyłącznie po stronie daemona.

## Transport

- **Linux / macOS**: Unix socket, domyślnie `{XDG_RUNTIME_DIR}/lithiumd.sock`, uprawnienia `0o600`
- **Windows**: named pipe, domyślnie `\\.\pipe\lithiumd`, `reject_remote_clients(true)`

Protokół: **JSON-lines** — jedno żądanie = jedna linia JSON zakończona `\n`, jedna odpowiedź = jedna linia JSON zakończona `\n`.

Maksymalny rozmiar linii: **4 MiB** (`IPC_MAX_LINE_BYTES`). Przekroczenie skutkuje zamknięciem połączenia.

Idle timeout: **300 sekund** (domyślnie; konfigurowalny przez `LITHIUMD_IPC_IDLE_TIMEOUT_SECS`, min. 5).

Maksymalna liczba równoległych połączeń: **1** (domyślnie; konfigurowalny przez `LITHIUMD_IPC_MAX_CONNECTIONS`, min. 1). Nadmiarowe połączenie jest odrzucane przy `accept` (klient nie dostaje żadnej odpowiedzi — po stronie klienta to wygląda jak natychmiastowy EOF/reset).

## Format żądania

```json
{
    "id": 1,
    "auth_token": "hex_token_64_znaki",
    "cmd": "nazwa_komendy",
    ...pola komendy...
}
```

- `id` — dowolna liczba całkowita; odpowiedź zwraca to samo `id`. Przy błędzie parsowania JSON (`bad_json`) odpowiedź zwraca `id: 0`, bo żądanie nie zostało jeszcze odczytane.
- `auth_token` — wymagany dla większości komend; pomijany (lub `null`) dla `ping`, `unlock_keystore`, `remote_delete`, `set_server_identity`, `set_server_url`
- `cmd` — nazwa komendy (snake_case, odpowiada wariantom `IpcCommand` w `lithiumd/src/ipc/types.rs`)

## Format odpowiedzi

```json
{
    "id": 1,
    "ok": true,
    "result": { ... },
    "error": null
}
```

Przy błędzie:
```json
{
    "id": 1,
    "ok": false,
    "error": "kod_bledu"
}
```

`result` i `error` są pomijane w JSON gdy `None` (`skip_serializing_if`), nie serializowane jako `null`.

## Autoryzacja IPC

Bez tokenu działają: `ping`, `unlock_keystore`, `remote_delete`, `set_server_identity`, `set_server_url` (`cmd_requires_auth` w `lithiumd/src/ipc/mod.rs`). Wszystkie pozostałe komendy wymagają `auth_token` w każdym żądaniu.

Token sesji jest emitowany po pomyślnym `unlock_keystore` jako pole `ipc_auth_token`, dopisane do `result` tej odpowiedzi. Token = 64 hex znaków (32 losowe bajty). Wydawany przy **każdym** udanym `unlock_keystore`, także gdy keystore był już odblokowany i podano to samo hasło ponownie.

Na **Linuxie** token jest dodatkowo wiązany z UID i PID klienta (odczytanym przez `SO_PEERCRED`). Żądania z innego PID lub UID zwracają `ipc_auth_failed`. Porównanie tokenu jest stałoczasowe (`subtle::ConstantTimeEq`).

Token jest unieważniany przez `lock_keystore` i `wipe_local`.

### Kody błędów autoryzacji

| Kod | Znaczenie |
|-----|-----------|
| `ipc_auth_required` | Brak tokenu (pustego lub `null`) albo brak aktywnej sesji |
| `ipc_auth_failed` | Niepoprawny token lub niepasujący UID/PID |
| `ipc_auth_issue_failed` | Tylko po `unlock_keystore`: nie udało się wygenerować tokenu (`random_32` zawiodło) |

### LITHIUMD_IPC_ALLOWED_UID

Niezależnie od tokenu sesji, na Linuksie `LITHIUMD_IPC_ALLOWED_UID` ogranicza, kto może nawet otworzyć połączenie. Sprawdzenie odbywa się **przed** odczytaniem jakiejkolwiek linii — połączenie z niedozwolonego UID jest po prostu zrywane (`continue` w pętli `accept` w `lithiumd/src/ipc/unix.rs`), klient nie dostaje żadnej odpowiedzi JSON, ani `ipc_auth_failed`, ani czegokolwiek innego. To inny mechanizm odmowy niż błędy auth tokenu powyżej.

## Stan daemona

Daemon przechodzi przez sekwencję stanów. Komendy wywołane poza kolejnością zwracają błąd.

```
start
  -> set_server_url (wymagane jako pierwsze — unlock_keystore zwraca server_url_not_set bez tego)
  -> set_server_identity (nieblokowane przez stan daemona, ale bez tego każde żądanie sieciowe
     do serwera i tak zawiedzie, więc w praktyce robione w tym samym momencie co set_server_url)
  -> keystore_locked (ui_state=keystore_locked)
  -> unlock_keystore
  -> ipc_auth_token wyemitowany, ui_state=needs_credentials
  -> set_credentials (wymagane po każdym unlock_keystore — credentials są tylko w pamięci)
  -> ui_state=needs_register (jeśli needs_register) albo storage_locked
  -> [register] (tylko gdy needs_register=true)
  -> unlock_storage
  -> ui_state=ready, komendy kontaktowe dostepne
```

`set_server_url` i `set_server_identity` nie są częścią stanu pilotowanego przez `ui_state` (nie mają własnej fazy w `ui_state`) — `ping.status.has_server_url`/`has_server_identity` istnieją jako osobne, niezależne flagi. Klient (np. GUI `lithiumg`) musi sam je sprawdzić i poprosić użytkownika o URL/identity przed wywołaniem `unlock_keystore`, inaczej dostanie `server_url_not_set`. `lithiumg` robi to dokładnie w tej kolejności — dwa pierwsze ekrany onboardingu to "Server URL" i "Server identity", zanim pojawi się ekran hasła do keystora.

Mimo że te dwa kroki sąsiadują w onboardingu, to dwa niezależne wejścia z rozłącznych źródeł: `set_server_url` przyjmuje adres wpisany przez użytkownika (służy wyłącznie do otwarcia połączenia HTTP), a `set_server_identity` przyjmuje bajty pliku, który użytkownik musi dostać kanałem out-of-band od operatora serwera i wybrać ręcznie z dysku (`server_identity_path` + `Browse…` w GUI). Daemon nigdy nie pobiera `data` dla `set_server_identity` sam, ani z adresu ustawionego przez `set_server_url`, ani z żadnego innego adresu sieciowego — nie istnieje i nie będzie istniał endpoint służący do automatycznej dystrybucji tożsamości serwera. To jest świadome — automatyczne dociąganie nowej tożsamości pozwoliłoby operatorowi (albo komuś, kto przejął serwer) podmienić klucze serwera bez wiedzy użytkownika.

`ping` zwraca aktualny stan we wszystkich fazach — patrz pełny opis pola `status` poniżej.

## Komendy

### `ping`

Bez autoryzacji.

```json
{ "id": 1, "cmd": "ping" }
```

Odpowiedź — zwraca surowy stan (`status`), zsyntetyzowaną fazę (`ui_state`) i listę komend, które klient powinien teraz wywołać (`actions_needed`):

```json
{
    "id": 1,
    "ok": true,
    "result": {
        "pong": true,
        "status": {
            "has_proto": false,
            "has_keys": false,
            "has_credentials": false,
            "has_data_password": false,
            "needs_register": true,
            "has_dek": false,
            "has_local_db": false,
            "has_server_url": false,
            "has_server_identity": false,
            "has_keystore_on_disk": false,
            "is_registered_on_disk": false,
            "has_local_db_on_disk": false,
            "first_run": true,
            "mk_rotation_error": false
        },
        "ui_state": "keystore_locked",
        "actions_needed": ["unlock_keystore"]
    }
}
```

`ui_state` to jedna z: `keystore_locked`, `needs_credentials`, `needs_register`, `storage_locked`, `ready`.

---

### `unlock_keystore`

Bez autoryzacji.

Odblokowuje lokalny keystore hasłem danych (`PasswordFileMkProvider`), startuje `MkRotator`, tworzy `ProtocolManager`. Emituje token sesji IPC.

```json
{
    "id": 1,
    "cmd": "unlock_keystore",
    "data_password": "HasloMinimum12Znakow!"
}
```

Wymagania `data_password` walidowane przez `PasswordPolicy::default()` (`validate_password`).

Jeśli keystore jest już odblokowany — porównuje hasło z bieżącym stałoczasowo; przy zgodności zwraca sukces (nowy token wydawany ponownie), przy niezgodności `bad_data_password`.

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "unlocked": true,
        "ipc_auth_token": "64hex..."
    }
}
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `bad_data_password` | Hasło nie spełnia polityki, albo nie zgadza się z już ustawionym |
| `passwords_must_be_distinct` | Hasło danych identyczne z już ustawionym hasłem konta |
| `crypto_error` | `KeyManager::start` nie powiódł się (np. uszkodzony plik klucza) |
| `internal_error` | `EphemeralStoreManager::new` zawiodło |
| `server_url_not_set` | Nie wywołano jeszcze `set_server_url` |

---

### `lock_keystore`

Wymaga auth.

Blokuje keystore i usuwa z pamięci wszystkie sekrety (`dek_plain`, `data_pass`, `account_creds`, `proto`, `local_db`, `keys`), unieważnia token IPC. Zatrzymuje `MkRotator`. Zawsze się powodzi.

```json
{ "id": 1, "auth_token": "...", "cmd": "lock_keystore" }
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "locked": true } }
```

---

### `set_credentials`

Wymaga auth.

Ustawia handler i hasło konta serwera. Dane przechowywane wyłącznie w pamięci (`SecretString`). Wymagane po każdym `unlock_keystore` przed `register`/`unlock_storage`.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "set_credentials",
    "handler": "alice",
    "password": "HasloKonta!1"
}
```

- `password` przechodzi `validate_password` (`PasswordPolicy`)
- `password` musi różnić się od `data_password` (jeśli już ustawione)

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "stored": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `bad_account_password` | Hasło konta nie spełnia polityki |
| `passwords_must_be_distinct` | Hasło konta identyczne z hasłem keystora |

---

### `register`

Wymaga auth + keystore odblokowany (`proto` ustawiony).

Rejestruje konto na serwerze. **Idempotentne**: jeśli `needs_register == false`, zwraca sukces bez żadnej akcji sieciowej.

```json
{ "id": 1, "auth_token": "...", "cmd": "register" }
```

Generuje losowy DEK (32B), szyfruje go hasłem konta (`Argon2id + AES-256-GCM-SIV`), wysyła do serwera. Serwer przechowuje zaszyfrowany blob i zwraca go przy każdym logowaniu.

Odpowiedź (pierwsza rejestracja):
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "registered": true,
        "capability": "hex..."
    }
}
```

Odpowiedź (już zarejestrowany — wywołanie ponowne):
```json
{ "id": 1, "ok": true, "result": { "registered": true } }
```
(bez pola `capability` — nie jest regenerowane).

`capability` to token do awaryjnego usunięcia konta bez logowania (patrz `remote_delete`). Serwer przechowuje wyłącznie jego hash. **Daemon nie przechowuje `capability` — po wyświetleniu w tej jednej odpowiedzi jest niedostępny.** Utrata = brak możliwości zdalnego usunięcia konta przez właściciela.

| Kod błędu | Znaczenie |
|-----------|-----------|
| `keystore_locked` | `proto` nie ustawiony (keystore zablokowany) |
| `missing_data_password` | Brak `data_password` w pamięci |
| `missing_account_credentials` | Brak `set_credentials` |
| `passwords_must_be_distinct` | Hasło danych = hasło konta |
| `crypto_error` | Generowanie lub wrap DEK-a zawiodło |
| `protocol_error` | Błąd sieciowy lub odpowiedzi serwera |
| `internal_error` | Konwersja DEK-a do `Byte32` zawiodła |
| `internal_state_error` | Niespodziewana kombinacja stanu (nie powinno wystąpić) |

---

### `unlock_storage`

Wymaga auth + keystore odblokowany + zarejestrowany.

Pobiera zaszyfrowany DEK z serwera, deszyfruje go i inicjalizuje lokalną bazę SQLite (jeśli jeszcze nie istnieje w pamięci).

```json
{ "id": 1, "auth_token": "...", "cmd": "unlock_storage" }
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "unlocked": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `keystore_locked` | `proto` nie ustawiony |
| `register_required` | `needs_register == true` |
| `missing_data_password` | Brak `data_password` w pamięci |
| `protocol_error` | Błąd pobierania DEK-a z serwera (np. brak `set_credentials`/login) |
| `crypto_error` | Deszyfrowanie DEK-a zawiodło |
| `internal_error` | Konwersja DEK-a do `Byte32` zawiodła |
| `storage_init_failed` | Inicjalizacja lokalnej bazy SQLite zawiodła |
| `internal_state_error` | Niespodziewana kombinacja stanu |

---

### `create_invite`

Wymaga auth + storage odblokowane.

Tworzy kod zaproszenia dla nowego lub istniejącego kontaktu.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "create_invite",
    "contact_id": null
}
```

- `contact_id`: `null` = nowy kontakt; hex = istniejący kontakt (ponowne zaproszenie, generuje kod z aktualnych kluczy publicznych)

Nowy kontakt: generuje `contact_id` (32B losowe) i kompletny zestaw kluczy per-kontakt (X25519, ML-KEM-1024, Ed25519, ML-DSA-87, 3 pary mailbox). Zapisuje stan w SQLite.

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contact_id": "hex64...",
        "code": "lci1:hex..."
    }
}
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `invalid_contact_id` | Podany `contact_id` nie jest poprawnym hex |
| `contact_not_found` | Podany `contact_id` nie istnieje w DB |
| `self_state_corrupt` | Stan kontaktu w DB nie deserializuje się |
| `json_error` | Serializacja nowego stanu zawiodła |
| `storage_error` | Błąd zapisu/odczytu DB |
| `internal_error` | Kodowanie kodu zaproszenia zawiodło |

---

### `accept_invite`

Wymaga auth + storage odblokowane.

Przyjmuje kod zaproszenia od drugiej strony.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "accept_invite",
    "code": "lci1:hex...",
    "contact_id": null,
    "label": "Alice"
}
```

- `contact_id: null` — nowe parowanie obustronne: dekoduje kod, generuje własny `contact_id` i klucze, zwraca `my_code` do odesłania drugiej stronie
- `contact_id: "hex..."` — przyjęcie od istniejącego kontaktu (jednostronne, kontakt musi istnieć i nie mieć jeszcze `peer` ustawionego): aktualizuje `peer_state`, `my_code` w odpowiedzi jest pustym stringiem

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contact_id": "hex64...",
        "my_code": "lci1:hex..."
    }
}
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `invalid_invite_code` | Kod nie deserializuje się (zły magic/wersja/długość) |
| `invalid_contact_id` | Podany `contact_id` nie jest poprawnym hex |
| `contact_not_found` | Podany `contact_id` nie istnieje w DB |
| `peer_already_set` | Kontakt już ma ustawionego peera — nie można przyjąć ponownie |
| `peer_state_corrupt` / `self_state_corrupt` | Stan kontaktu w DB nie deserializuje się |
| `json_error` | Serializacja nowego stanu zawiodła |
| `storage_error` | Błąd zapisu/odczytu DB |
| `internal_error` | Generowanie własnych kluczy lub kodowanie `my_code` zawiodło |

---

### `contacts_list`

Wymaga auth + storage odblokowane.

```json
{ "id": 1, "auth_token": "...", "cmd": "contacts_list" }
```

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contacts": [
            { "contact_id": "hex64...", "label": "Alice", "peer_set": true }
        ]
    }
}
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `storage_error` | Błąd odczytu DB |
| `peer_state_corrupt` | Stan kontaktu w DB nie deserializuje się |

---

### `contact_send`

Wymaga auth + storage odblokowane + keystore odblokowane (`proto`).

Szyfruje i wysyła wiadomość do kontaktu. Tryb szyfrowania (`bootstrap`/`ratchet`/`prekey_recover`) jest wybierany automatycznie wewnątrz `encrypt_for_peer`, klient nie wybiera go w żądaniu.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_send",
    "contact_id": "hex64...",
    "plaintext": "Tresc wiadomosci"
}
```

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": { "sent": true, "mailbox_gen": 0 }
}
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `keystore_locked` | `proto` nie ustawiony |
| `invalid_contact_id` | `contact_id` nie jest poprawnym 32-bajtowym hex |
| `contact_not_found` | Kontakt nie istnieje w DB |
| `self_state_corrupt` / `peer_state_corrupt` | Stan kontaktu w DB nie deserializuje się |
| `crypto_error` | Inicjalizacja keyringu/mailboxa lub szyfrowanie zawiodło |
| `invalid_prekey_id` / `storage_error` | Generowanie/zapis lokalnych prekeys zawiodło |
| `need_recover_but_no_remote_prekey` | Peer wymaga recovery, ale nie opublikował prekey |
| `protocol_error` | Wysyłka do serwera (`/msg/send`) zawiodła |
| `json_error` | Serializacja nowego stanu lub wiadomości do zapisu zawiodła |

`peer_set == false` nie jest osobnym błędem — w praktyce skończy się jednym z błędów stanu kontaktu wyżej, bo brak peera oznacza brak kluczy do szyfrowania.

---

### `contact_fetch`

Wymaga auth + storage odblokowane + keystore odblokowane (`proto`).

Pobiera wiadomości od kontaktu z serwera (do 4 generacji mailbox naraz). Usuwa je z serwera atomowo (one-time fetch). Jednoczesne wywołania dla tego samego `contact_id` są serializowane (`contact_fetch_locks`).

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_fetch",
    "contact_id": "hex64..."
}
```

Odpowiedź — **nie** ma top-level liczników `fetched`/`failed`; zamiast tego tablica wyników per wiadomość, każdy z `ok`/`err`:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "messages": [
            { "ok": true, "ui": { "mode": "bootstrap" }, "text": "Tresc", "mailbox_gen": 0 },
            { "ok": false, "err": "duplicate", "mailbox_gen": 0 }
        ]
    }
}
```

Top-level błędy (przed iteracją po wiadomościach):

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `keystore_locked` | `proto` nie ustawiony |
| `invalid_contact_id` | `contact_id` nie jest poprawnym 32-bajtowym hex |
| `contact_not_found` | Kontakt nie istnieje w DB |
| `self_state_corrupt` / `peer_state_corrupt` | Stan kontaktu w DB nie deserializuje się |
| `crypto_error` | Inicjalizacja keyringu/mailboxa zawiodła |
| `protocol_error` | Pobranie z serwera (`/msg/fetch`) zawiodło |
| `storage_error` | Zapis nowego stanu/wiadomości do DB zawiódł |
| `json_error` | Serializacja nowego stanu zawiodła |

Błędy per wiadomość (pole `err` w elemencie tablicy `messages`, żądanie jako całość kończy się `ok: true`): `invalid_hex`, `bad_wire`, `invalid_utf8`, `duplicate`, `potentially_harmful_message`, `decrypt_failed`, `to_id_unknown`, `prekey_lookup_failed`, `prekey_recovery_failed`.

---

### `messages_list`

Wymaga auth + storage odblokowane.

Zwraca stronę wiadomości z danym kontaktem (paginacja).

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "messages_list",
    "contact_id": "hex64...",
    "limit": 50,
    "before_id": null
}
```

- `limit`: domyślnie 50, clampowane do 1–200
- `before_id`: `null` = najnowsze; ID wiadomości = starsze od podanego

Wyniki zwracane w kolejności chronologicznej (od najstarszych do najnowszych w bieżącej stronie).

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "messages": [
            {
                "id": 42,
                "direction": "in",
                "kind": "text",
                "text": "Tresc",
                "ui": {},
                "created_at": "2024-01-01T12:00:00+00:00"
            }
        ],
        "paging": {
            "has_more": false,
            "next_before_id": null
        }
    }
}
```

`direction` to `"in"` lub `"out"` (nie `"inbound"`/`"outbound"`). `kind` pochodzi z zapisanej wiadomości (`"text"` dla zwykłej treści, `"unknown"` gdy nie udało się jej rozkodować). `paging` jest zagnieżdżone, nie spłaszczone.

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `invalid_contact_id` | `contact_id` nie jest poprawnym hex |
| `storage_error` | Błąd odczytu DB |

---

### `contact_verify_emoji`

Wymaga auth + storage odblokowane.

Generuje 12-znakowy SAS (fingerprint) do weryfikacji tożsamości out-of-band. Obie strony muszą wywołać i porównać wyniki. Weryfikacja jest czysto lokalna — nie wymaga połączenia z serwerem. Wyprowadzenie pełne opisane w [crypto-protocol.md](crypto-protocol.md#weryfikacja-tożsamości-out-of-band).

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_verify_emoji",
    "contact_id": "hex64..."
}
```

Odpowiedź — pole nazywa się `emojis` (liczba mnoga), nie `emoji`:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "emojis": ["A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M"]
    }
}
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `invalid_contact_id` | `contact_id` nie jest poprawnym hex |
| `contact_not_found` | Kontakt nie istnieje w DB |
| `self_state_corrupt` / `peer_state_corrupt` | Stan kontaktu w DB nie deserializuje się |
| `peer_not_set` | Peer nie odesłał jeszcze swojego kodu zaproszenia |
| `internal_error` | Wyprowadzenie SAS zawiodło |

---

### `contact_forget`

Wymaga auth + storage odblokowane.

Usuwa kontakt i wszystkie jego wiadomości oraz prekeys z lokalnej bazy. Operacja nieodwracalna.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_forget",
    "contact_id": "hex64..."
}
```

Odpowiedź — pole nazywa się `forgot`, nie `forgotten`:
```json
{ "id": 1, "ok": true, "result": { "forgot": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `storage_locked` | Storage nie odblokowane |
| `invalid_contact_id` | `contact_id` nie jest poprawnym hex |
| `contact_not_found` | Kontakt nie istnieje w DB |
| `storage_error` | Błąd usuwania z DB |

---

### `set_server_url`

Bez autoryzacji.

Ustawia URL serwera relay daemona, zapisuje go trwale do pliku `{data_dir}/server_url`.

```json
{
    "id": 1,
    "cmd": "set_server_url",
    "url": "https://relay.example.com"
}
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "saved": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `invalid_url` | URL nie parsuje się |
| `write_failed` | Zapis pliku `server_url` zawiódł |

---

### `set_server_identity`

Bez autoryzacji.

Ustawia tożsamość serwera (cztery klucze publiczne, zakodowane jak opisano w [crypto-protocol.md](crypto-protocol.md#format-pliku-serveridentity)) — **nie** ścieżkę do pliku na dysku. Klient musi sam wczytać plik `server.identity` (dostarczony przez administratora serwera kanałem OOB) i przesłać jego zawartość jako hex w polu `data`.

```json
{
    "id": 1,
    "cmd": "set_server_identity",
    "data": "hex-encoded bytes pliku server.identity"
}
```

Zapisuje bajty do `state.identity_path` na dysku i natychmiast invaliduje cache bootstrapu (`proto.invalidate_bootstrap_cache()`) — nowa tożsamość obowiązuje od następnego żądania do serwera, bez potrzeby `lock_keystore`/`unlock_keystore`. Patrz [security-model.md](security-model.md#zmiana-serveridentity-jest-celowo-bolesna).

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "saved": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `server_identity_bad_hex` | `data` nie jest poprawnym hex |
| `server_identity_invalid:<szczegół>` | Dane nie parsują się jako poprawny `server.identity` (np. zły magic, brakujący klucz) |
| `internal_error` | Zapis pliku na dysk zawiódł |

---

### `remote_delete`

Bez autoryzacji.

Usuwa konto z serwera przy użyciu capability uzyskanego przy rejestracji. Nie wymaga aktywnej sesji ani hasła — działa offline, niezależnie od stanu keystora.

```json
{
    "id": 1,
    "cmd": "remote_delete",
    "capability": "hex..."
}
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "remote_delete_requested": true } }
```

Serwer zawsze zwraca 204 niezależnie od poprawności capability — daemon raportuje sukces jeśli żądanie dotarło do serwera, nie czy konto faktycznie zostało usunięte.

| Kod błędu | Znaczenie |
|-----------|-----------|
| `internal_error` | Inicjalizacja `EphemeralStoreManager`/HTTP klienta zawiodła |
| `server_url_not_set` | Nie wywołano jeszcze `set_server_url` |
| `protocol_error` | Błąd sieciowy podczas wysyłki |

---

### `delete_account`

Wymaga auth + keystore odblokowany. **Komenda nieopisana we wcześniejszych wersjach tego dokumentu** — istnieje od dawna w kodzie (`lithiumd/src/commands/delete_account.rs`).

Inny mechanizm niż `remote_delete`: usuwa konto przez aktywną sesję serwera (`Endpoint::Delete`, `AuthMode::JwtUser` — wymaga zalogowania), nie przez offline capability token. Po pomyślnym usunięciu na serwerze, wykonuje pełny lokalny wipe (tak jak `wipe_local`).

```json
{ "id": 1, "auth_token": "...", "cmd": "delete_account" }
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "deleted": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `keystore_locked` | `proto` nie ustawiony |
| `protocol_error` | Usunięcie konta na serwerze zawiodło (np. brak loginu) — lokalne dane **nie** są usuwane w tym wypadku |
| `account_deleted_but_local_wipe_failed` | Konto usunięte na serwerze, ale lokalny wipe zawiódł — stan niespójny, wymaga ręcznej interwencji |

---

### `wipe_local`

Wymaga auth.

Usuwa całe `{data_dir}` — wszystkie klucze, bazę SQLite, stan lokalny. Operacja bezpowrotna. Nie kontaktuje serwera.

```json
{ "id": 1, "auth_token": "...", "cmd": "wipe_local" }
```

Sekwencja:
1. Blokuje keystore (usuwa sekrety z pamięci)
2. Nadpisuje każdy plik losowymi bajtami (chunki 1 MB, `fsync` po każdym pliku)
3. `fsync` katalogu (Unix)
4. Usuwa pliki i katalogi
5. Ustawia flagę `needs_register`

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "wiped": true, "best_effort": true } }
```

`best_effort: true` oznacza, że nadpisywanie jest best-effort — na systemach plików z copy-on-write lub SSD z wear leveling fizyczne usunięcie danych nie jest gwarantowane.

| Kod błędu | Znaczenie |
|-----------|-----------|
| `wipe_failed` | Nadpisanie lub usunięcie plików zawiodło |

---

### `shutdown`

Wymaga auth.

Wysyła sygnał zamknięcia do głównej pętli daemona, blokuje keystore. Zawsze zwraca sukces, niezależnie czy sygnał shutdown był jeszcze dostępny (idempotentne — drugie wywołanie po pierwszym `shutdown` po prostu nic nie wysyła, ale wciąż zwraca `ok: true`).

```json
{ "id": 1, "auth_token": "...", "cmd": "shutdown" }
```

Odpowiedź — pole nazywa się `shutting_down`, nie `shutdown`:
```json
{ "id": 1, "ok": true, "result": { "shutting_down": true } }
```

## Pełna lista kodów błędów

| Kod | Komenda(y) | Znaczenie |
|-----|------------|-----------|
| `bad_json` | wszystkie (poziom parsowania linii) | Linia nie parsuje się jako `IpcRequest` |
| `ipc_auth_required` | komendy wymagające auth | Brak tokenu lub brak aktywnej sesji |
| `ipc_auth_failed` | komendy wymagające auth | Niepoprawny token lub UID/PID nie pasuje |
| `ipc_auth_issue_failed` | `unlock_keystore` | Błąd generowania tokenu sesji |
| `bad_data_password` | `unlock_keystore` | Hasło nie spełnia polityki lub nie zgadza się z bieżącym |
| `bad_account_password` | `set_credentials` | Hasło konta nie spełnia polityki |
| `passwords_must_be_distinct` | `unlock_keystore`, `set_credentials`, `register` | Hasło konta = hasło danych |
| `keystore_locked` | `register`, `unlock_storage`, `contact_send`, `contact_fetch`, `delete_account` | `proto` nie ustawiony (keystore zablokowany) |
| `missing_data_password` | `register`, `unlock_storage` | Brak `data_password` w pamięci |
| `missing_account_credentials` | `register` | Brak `set_credentials` |
| `register_required` | `unlock_storage` | `needs_register == true` |
| `storage_locked` | komendy kontaktowe i wiadomości | Lokalna baza nie zainicjalizowana |
| `storage_init_failed` | `unlock_storage` | Inicjalizacja lokalnej bazy SQLite zawiodła |
| `storage_error` | komendy operujące na DB | Błąd odczytu/zapisu SQLite |
| `internal_state_error` | `register`, `unlock_storage` | Niespodziewana kombinacja stanu |
| `crypto_error` | `unlock_keystore`, `register`, `unlock_storage`, `contact_send`, `contact_fetch` | Błąd kryptograficzny (deszyfrowanie, generowanie kluczy) |
| `protocol_error` | komendy kontaktujące serwer | Błąd sieciowy lub odpowiedzi serwera |
| `internal_error` | wiele | Nieoczekiwany błąd wewnętrzny |
| `invalid_contact_id` | komendy kontaktowe | `contact_id` nie jest poprawnym hex / 32 bajty |
| `contact_not_found` | komendy kontaktowe | Nieznany `contact_id` |
| `self_state_corrupt` / `peer_state_corrupt` | komendy kontaktowe | Stan kontaktu w DB nie deserializuje się |
| `peer_not_set` | `contact_verify_emoji` | Peer nie odesłał kodu zaproszenia |
| `peer_already_set` | `accept_invite` | Kontakt już ma peera, nie można przyjąć ponownie |
| `invalid_invite_code` | `accept_invite` | Kod zaproszenia nie parsuje się |
| `need_recover_but_no_remote_prekey` | `contact_send` | Wymagane recovery, ale peer nie opublikował prekey |
| `json_error` | komendy zapisujące stan | Serializacja stanu kontaktu/wiadomości zawiodła |
| `invalid_url` | `set_server_url` | URL nie parsuje się |
| `write_failed` | `set_server_url` | Zapis pliku `server_url` zawiódł |
| `server_identity_bad_hex` | `set_server_identity` | `data` nie jest poprawnym hex |
| `server_identity_invalid:<...>` | `set_server_identity` | Dane nie są poprawnym `server.identity` |
| `server_url_not_set` | `unlock_keystore`, `remote_delete` | Nie wywołano `set_server_url` |
| `account_deleted_but_local_wipe_failed` | `delete_account` | Konto usunięte na serwerze, lokalny wipe zawiódł |
| `wipe_failed` | `wipe_local` | Błąd usuwania plików |

Błędy per-wiadomość zwracane wewnątrz tablicy `messages` przez `contact_fetch` (`invalid_hex`, `bad_wire`, `invalid_utf8`, `duplicate`, `potentially_harmful_message`, `decrypt_failed`, `to_id_unknown`, `prekey_lookup_failed`, `prekey_recovery_failed`) nie kończą żądania błędem — całe żądanie zwraca `ok: true`, błąd jest tylko w elemencie tablicy.

## Zmienne środowiskowe

| Zmienna | Domyślnie | Opis |
|---------|-----------|------|
| `LITHIUMD_DATA_DIR` | platformowy katalog danych (np. `~/.local/share/lithiumd`) | Katalog danych daemona |
| `LITHIUMD_SOCKET_PATH` | `{XDG_RUNTIME_DIR}/lithiumd.sock` | Ścieżka Unix socketa |
| `LITHIUMD_PIPE_NAME` | `\\.\pipe\lithiumd` | Nazwa named pipe (Windows) |
| `LITHIUMD_SERVER_IDENTITY` | `{data_dir}/server.identity` | Ścieżka pliku tożsamości serwera |
| `LITHIUMD_IPC_MAX_CONNECTIONS` | `1` | Max równoległych połączeń IPC |
| `LITHIUMD_IPC_IDLE_TIMEOUT_SECS` | `300` | Idle timeout połączenia (min 5) |
| `LITHIUMD_IPC_ALLOWED_UID` | — | Dozwolony UID (Linux; brak = bez ograniczenia); odmowa zrywa połączenie bez odpowiedzi JSON |
