# Referencja IPC daemona Lithium

Daemon `lithiumd` wystawia lokalny endpoint IPC umożliwiający GUI (lub innemu klientowi) sterowanie wszystkimi operacjami kryptograficznymi. Klucze prywatne istnieją wyłącznie po stronie daemona.

## Transport

- **Linux / macOS**: Unix socket, domyślnie `{XDG_RUNTIME_DIR}/lithiumd.sock`, uprawnienia `0o600`
- **Windows**: named pipe, domyślnie `\\.\pipe\lithiumd`, `reject_remote_clients(true)`

Protokół: **JSON-lines** — jedno żądanie = jedna linia JSON zakończona `\n`, jedna odpowiedź = jedna linia JSON zakończona `\n`.

Maksymalny rozmiar linii: **4 MB**. Przekroczenie skutkuje zamknięciem połączenia.

Idle timeout: **300 sekund** (domyślnie; konfigurowalny przez `LITHIUMD_IPC_IDLE_TIMEOUT_SECS`).

Maksymalna liczba równoległych połączeń: **1** (domyślnie; konfigurowalny przez `LITHIUMD_IPC_MAX_CONNECTIONS`). Nadmiarowe połączenie dostaje EOF.

## Format żądania

```json
{
    "id": 1,
    "auth_token": "hex_token_64_znaki",
    "cmd": "nazwa_komendy",
    ...pola komendy...
}
```

- `id` — dowolna liczba całkowita; odpowiedź zwraca to samo `id`
- `auth_token` — wymagany dla większości komend; pomijany (lub `null`) dla `ping` i `unlock_keystore`
- `cmd` — nazwa komendy (snake_case)

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
    "result": null,
    "error": "kod_bledu"
}
```

## Autoryzacja IPC

Tylko `ping` i `unlock_keystore` nie wymagają tokenu. Wszystkie pozostałe komendy wymagają `auth_token` w każdym żądaniu.

Token sesji jest emitowany po pomyślnym `unlock_keystore` jako pole `ipc_auth_token` w odpowiedzi. Token = 64 hex znaków (32 losowe bajty).

Na **Linuxie** token jest dodatkowo wiązany z UID i PID klienta (odczytanym przez `SO_PEERCRED`). Żądania z innego PID lub UID zwracają `ipc_auth_failed`.

Token jest unieważniany przez `lock_keystore` i `wipe_local`.

### Kody błędów autoryzacji

| Kod | Znaczenie |
|-----|-----------|
| `ipc_auth_required` | Brak tokenu lub keystore zablokowany |
| `ipc_auth_failed` | Niepoprawny token lub niepassujący UID/PID |

## Stan daemona

Daemon przechodzi przez sekwencję stanów. Komendy wywołane poza kolejnością zwracają błąd.

```
start
  -> keystore_locked=true, needs_register=?, storage_locked=true
  -> unlock_keystore
  -> keystore_locked=false, ipc_auth_token wyemitowany
  -> set_credentials (wymagane przed register/unlock_storage po każdym restarcie)
  -> [register] (tylko gdy needs_register=true)
  -> unlock_storage
  -> storage_locked=false, komendy kontaktowe dostepne
```

`ping` zwraca aktualny stan we wszystkich fazach.

## Komendy

### `ping`

Bez autoryzacji.

Zwraca aktualny stan daemona.

```json
{ "id": 1, "cmd": "ping" }
```

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "keystore_locked": true,
        "needs_register": false,
        "storage_locked": true,
        "needs_credentials": true
    }
}
```

---

### `unlock_keystore`

Bez autoryzacji.

Odblokowuje lokalny keystore hasłem danych. Emituje token sesji IPC.

```json
{
    "id": 1,
    "cmd": "unlock_keystore",
    "data_password": "HasloMinimum8znakow!"
}
```

Wymagania `data_password`: min 8 znaków, wielkie/małe litery, cyfry, znaki specjalne, bez spacji.

Jeśli keystore jest już odblokowany — porównuje hasło z bieżącym; sukces lub błąd `keystore_already_unlocked`.

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
| `weak_password` | Hasło nie spełnia polityki |
| `keystore_already_unlocked` | Podano błędne hasło przy już odblokowanym keystore |
| `keystore_unlock_failed` | Błąd odczytu pliku klucza (np. błędne hasło) |

---

### `lock_keystore`

Wymaga auth.

Blokuje keystore i usuwa z pamięci wszystkie sekrety: `dek_plain`, `data_pass`, `account_creds`, `proto`, `local_db`, `keys`, token IPC. Zatrzymuje `MkRotator`.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "lock_keystore"
}
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "locked": true } }
```

---

### `set_credentials`

Wymaga auth.

Ustawia handler i hasło konta serwera. Dane przechowywane wyłącznie w pamięci (`SecretString`). Wymagane po każdym `unlock_keystore` przed `unlock_storage`.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "set_credentials",
    "handler": "alice",
    "password": "HasloKonta!1"
}
```

- `handler` i `password` przechodzą walidację `PasswordPolicy`
- `password` musi różnić się od `data_password`

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "set": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `weak_password` | Hasło nie spełnia polityki |
| `passwords_must_differ` | Hasło konta identyczne z hasłem keystora |

---

### `register`

Wymaga auth. Wymaga: keystore odblokowany + credentials ustawione + `needs_register == true`.

Rejestruje konto na serwerze. Wywołuje się raz na nowym urządzeniu.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "register"
}
```

Generuje losowy DEK (32B), szyfruje go hasłem konta (`Argon2id + AES-256-GCM-SIV`), wysyła do serwera. Serwer przechowuje zaszyfrowany blob i zwraca go przy każdym logowaniu.

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "registered": true,
        "remote_delete_capability": "hex64bajtow"
    }
}
```

`remote_delete_capability` to 32-bajtowy token do awaryjnego usunięcia konta bez logowania. Serwer przechowuje wyłącznie SHA-256 tego tokenu. **Capability nie jest przechowywany przez daemona — po wyświetleniu jest niedostępny.** Utrata = brak możliwości zdalnego usunięcia konta przez właściciela.

| Kod błędu | Znaczenie |
|-----------|-----------|
| `already_registered` | `needs_register == false` |
| `credentials_not_set` | Brak `set_credentials` |
| `register_failed` | Błąd sieciowy lub serwera |

---

### `unlock_storage`

Wymaga auth. Wymaga: keystore odblokowany + zarejestrowany + credentials ustawione.

Pobiera zaszyfrowany DEK z serwera, deszyfruje go i inicjalizuje lokalną bazę SQLite.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "unlock_storage"
}
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "unlocked": true } }
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `not_registered` | `needs_register == true` |
| `credentials_not_set` | Brak `set_credentials` |
| `storage_unlock_failed` | Błąd sieciowy, serwera lub deszyfrowania DEK |

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

- `contact_id`: `null` = nowy kontakt; hex 64 znaków = istniejący kontakt (ponowne zaproszenie)

Nowy kontakt: generuje `contact_id` (32B losowe) i kompletny zestaw kluczy per-kontakt (X25519, ML-KEM-1024, Ed25519, ML-DSA-87, 3 pary mailbox). Zapisuje stan w SQLite.

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contact_id": "hex64...",
        "invite_code": "lci1:hex..."
    }
}
```

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
- `contact_id: "hex..."` — przyjęcie od istniejącego kontaktu (jednostronne): aktualizuje `peer_state`, `my_code` w odpowiedzi jest pusty

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

---

### `contacts_list`

Wymaga auth + storage odblokowane.

Zwraca listę kontaktów z ich statusami.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contacts_list"
}
```

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contacts": [
            {
                "contact_id": "hex64...",
                "label": "Alice",
                "peer_set": true
            }
        ]
    }
}
```

---

### `contact_send`

Wymaga auth + storage odblokowane. Wymaga `peer_set == true`.

Szyfruje i wysyła wiadomość do kontaktu.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_send",
    "contact_id": "hex64...",
    "plaintext": "Tresc wiadomosci"
}
```

Tryb szyfrowania: `bootstrap` (pierwsza wiadomość), `ratchet` (po wymianie kluczy) lub `prekey_recover` (recovery po desynchronizacji).

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": { "sent": true }
}
```

| Kod błędu | Znaczenie |
|-----------|-----------|
| `contact_not_found` | `contact_id` nie istnieje w DB |
| `peer_not_set` | Peer nie odesłał jeszcze swojego kodu zaproszenia |
| `send_failed` | Błąd sieciowy lub serwera |

---

### `contact_fetch`

Wymaga auth + storage odblokowane.

Pobiera wiadomości od kontaktu z serwera (wszystkie dostępne generacje mailbox). Usuwa je z serwera atomowo.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_fetch",
    "contact_id": "hex64..."
}
```

Jednoczesne wywołania dla tego samego `contact_id` są serializowane (`contact_fetch_locks`).

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "fetched": 3,
        "failed": 0
    }
}
```

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

- `limit`: 1–200 (clampowane)
- `before_id`: `null` = najnowsze; ID wiadomości = starsze od podanego

Wyniki zwracane w kolejności chronologicznej (od najstarszych).

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "messages": [
            {
                "id": 42,
                "direction": "inbound",
                "content": "Tresc",
                "created_at": "2024-01-01T12:00:00Z"
            }
        ],
        "has_more": false
    }
}
```

---

### `contact_verify_emoji`

Wymaga auth + storage odblokowane.

Generuje 6 emoji do weryfikacji tożsamości out-of-band. Obie strony muszą wywołać i porównać wyniki.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_verify_emoji",
    "contact_id": "hex64..."
}
```

Wyprowadzenie:
```
shared = ECDH(self_x_priv, peer_x_pub)
6B = HKDF(shared, salt=sorted(cid_a || cid_b), info="lithiumd/verify-emoji/v1")
emoji[i] = EMOJI_TABLE[bajt[i] mod 64]
```

Weryfikacja jest czysto lokalna — nie wymaga połączenia z serwerem.

Odpowiedź:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "emoji": ["A", "B", "C", "D", "E", "F"]
    }
}
```

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

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "forgotten": true } }
```

---

### `set_server_url`

Bez autoryzacji.

Ustawia URL serwera relay daemona.

```json
{
    "id": 1,
    "cmd": "set_server_url",
    "url": "https://relay.example.com"
}
```

---

### `set_server_identity`

Bez autoryzacji.

Ładuje plik `server.identity` (klucze publiczne serwera). Plik musi być dostarczony przez administratora serwera.

```json
{
    "id": 1,
    "cmd": "set_server_identity",
    "path": "/ścieżka/do/server.identity"
}
```

---

### `remote_delete`

Bez autoryzacji.

Usuwa konto z serwera przy użyciu capability uzyskanego przy rejestracji. Nie wymaga aktywnej sesji ani hasła.

```json
{
    "id": 1,
    "cmd": "remote_delete",
    "capability": "hex64bajtow"
}
```

Capability to 32-bajtowy token wygenerowany przez serwer przy rejestracji. Serwer przechowuje wyłącznie SHA-256 — nie może go odtworzyć. Utrata capability = niemożność zdalnego usunięcia konta przez właściciela.

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "remote_delete_requested": true } }
```

Serwer zawsze zwraca 204 niezależnie od poprawności capability — daemon raportuje sukces jeśli żądanie dotarło do serwera, nie czy konto faktycznie zostało usunięte.

---

### `wipe_local`

Wymaga auth.

Usuwa całe `{data_dir}` — wszystkie klucze, bazę SQLite, stan lokalny. Operacja bezpowrotna.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "wipe_local"
}
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

---

### `shutdown`

Wymaga auth.

Wysyła sygnał zamknięcia do głównej pętli daemona.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "shutdown"
}
```

Odpowiedź:
```json
{ "id": 1, "ok": true, "result": { "shutdown": true } }
```

## Pełna lista kodów błędów

| Kod | Komenda | Znaczenie |
|-----|---------|-----------|
| `ipc_auth_required` | wszystkie | Brak tokenu lub keystore zablokowany |
| `ipc_auth_failed` | wszystkie | Niepoprawny token lub UID/PID nie pasuje |
| `ipc_auth_issue_failed` | `unlock_keystore` | Błąd generowania tokenu sesji |
| `weak_password` | `unlock_keystore`, `set_credentials` | Hasło nie spełnia polityki |
| `passwords_must_differ` | `set_credentials` | Hasło konta identyczne z hasłem keystora |
| `keystore_already_unlocked` | `unlock_keystore` | Keystore już odblokowany, błędne hasło |
| `keystore_unlock_failed` | `unlock_keystore` | Błąd deszyfrowania keystora |
| `already_registered` | `register` | `needs_register == false` |
| `credentials_not_set` | `register`, `unlock_storage` | Brak `set_credentials` |
| `register_failed` | `register` | Błąd rejestracji na serwerze |
| `not_registered` | `unlock_storage` | `needs_register == true` |
| `storage_unlock_failed` | `unlock_storage` | Błąd pobierania DEK lub inicjalizacji DB |
| `contact_not_found` | komendy kontaktowe | Nieznany `contact_id` |
| `peer_not_set` | `contact_send` | Peer nie odesłał kodu zaproszenia |
| `send_failed` | `contact_send` | Błąd sieciowy lub serwera |
| `wipe_failed` | `wipe_local` | Błąd usuwania plików |
| `internal_error` | dowolna | Nieoczekiwany błąd wewnętrzny |

## Zmienne środowiskowe

| Zmienna | Domyślnie | Opis |
|---------|-----------|------|
| `LITHIUMD_DATA_DIR` | `~/.local/share/lithiumd` | Katalog danych daemona |
| `LITHIUMD_SOCKET_PATH` | `{XDG_RUNTIME_DIR}/lithiumd.sock` | Ścieżka Unix socketa |
| `LITHIUMD_PIPE_NAME` | `\\.\pipe\lithiumd` | Nazwa named pipe (Windows) |
| `LITHIUMD_IPC_MAX_CONNECTIONS` | `1` | Max równoległych połączeń IPC |
| `LITHIUMD_IPC_IDLE_TIMEOUT_SECS` | `300` | Idle timeout połączenia (min 5) |
| `LITHIUMD_IPC_ALLOWED_UID` | — | Dozwolony UID (Linux; brak = bez ograniczenia) |