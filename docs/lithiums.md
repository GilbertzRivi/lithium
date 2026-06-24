# lithiums — serwer relay Lithium

Serwer REST dla komunikatora Lithium, zbudowany na frameworku Poem z bazą PostgreSQL (via SeaORM). 
Serwer jest jawnie **niegodny zaufania** — przechowuje i przekazuje zaszyfrowane dane, 
nigdy nie deszyfruje treści wiadomości ani nie ma dostępu do kluczy prywatnych klientów.

## Miejsce w architekturze

```
lithiumg (GUI)
  ↕ IPC
lithiumd (daemon klienta)          ← używa lithiums jako relay
  ↕ HTTPS + Kyberbox (X25519 + ML-KEM-1024)
lithiums (serwer relay)   ← ten crate
  - PostgreSQL: rekordy użytkowników + kolejkowanie wiadomości
  - EphemeralStoreManager: pamięciowy cache TTL (klucze sesji, JWT, limity, replay)
  - KeyManager<PlainFileMkProvider>: klucze podpisujące/szyfrujące serwera
```

```
src/
├── main.rs               — punkt wejścia: zmienne środowiskowe, KeyManager, DB, MkRotator, serwer Poem
├── lib.rs                — tablica tras, podpięcie CryptoMiddleware + GuardMiddleware
├── state.rs              — AppState (współdzielony między handlerami)
├── error.rs              — AppError → odpowiedź HTTP
├── mk_rotator.rs         — zadanie rotacji MK w tle
├── transport/
│   └── mod.rs            — CryptoMode, AuthMode, JWT, limity, deszyfrowanie żądań, szyfrowanie odpowiedzi
├── middleware/
│   ├── crypto.rs         — CryptoMiddleware (deszyfrowanie/autentykacja per trasa)
│   └── guard.rs          — GuardMiddleware (limity rozmiaru, anti-replay, rate limiting IP)
├── api/
│   ├── handshake.rs      — POST /shake
│   ├── user.rs           — POST /user/register, POST /user/login
│   └── messages.rs       — POST /msg/send, POST /msg/fetch
└── db/
    ├── mod.rs            — połączenie z PostgreSQL z DATABASE_URL
    ├── models.rs         — definicje encji SeaORM (users, messages)
    └── repo.rs           — ServerDbExt: operacje DB z szyfrowaniem kopertowym
```

## Konfiguracja

`lithiums` nasłuchuje na czystym HTTP. TLS terminuje reverse proxy (nginx, Caddy itp.) umieszczony przed procesem. Domyślny bind `127.0.0.1` zakłada, że proxy działa na tym samym hoście.

Cała konfiguracja przez zmienne środowiskowe (obsługa `.env` przez `dotenvy`):

| Zmienna                  | Wymagana | Domyślnie           | Opis                                             |
|--------------------------|----------|---------------------|--------------------------------------------------|
| `DB_HOST`                | tak      | —                   | Host PostgreSQL                                  |
| `DB_PORT`                | nie      | `5432`              | Port PostgreSQL                                  |
| `DB_USER`                | tak      | —                   | Użytkownik bazy danych                           |
| `DB_PASSWORD_FILE`       | tak      | —                   | Ścieżka do pliku z hasłem (Docker secret)        |
| `DB_NAME`                | tak      | —                   | Nazwa bazy danych                                |
| `DB_MAX_CONNECTIONS`     | nie      | `20`                | Maksymalna liczba połączeń w puli                |
| `DB_MIN_CONNECTIONS`     | nie      | `2`                 | Minimalna liczba utrzymywanych połączeń          |
| `LITHIUM_KEYS_DIR`       | nie      | `/var/lib/lithiums` | Katalog plików kluczy i server.identity          |
| `LITHIUM_BIND`           | nie      | `127.0.0.1`         | Adres nasłuchiwania                              |
| `LITHIUM_PORT`           | nie      | `4108`              | Port nasłuchiwania                               |
| `LITHIUM_MK_ROTATE_SECS` | nie     | `3600`              | Interwał rotacji MK w sekundach                  |
| `LITHIUMS_SEND_POW_BITS` | nie      | `18`                | Trudność proof-of-work (bity zer wiodących) na `/msg/send` |

Providery master key (`LITHIUM_MK_PROVIDER`) i zmienne TPM opisuje [deploy-instructions.md](deploy-instructions.md).

Pozostałe parametry puli: connect/acquire timeout 10 s, idle timeout 600 s, max lifetime połączenia 1800 s.

## Sekwencja startu

1. Parsowanie i walidacja zmiennych środowiskowych
2. Załadowanie/inicjalizacja `KeyManager<PlainFileMkProvider>` z `LITHIUM_KEYS_DIR` (przy pierwszym uruchomieniu generuje nowe klucze)
3. Uruchomienie zadania `MkRotator` w tle (tick co 30s, rotuje jeśli minął `LITHIUM_MK_ROTATE_SECS`)
4. Połączenie z PostgreSQL (`DATABASE_URL`), wywołanie `DataManager::init()` (migracje, inicjalizacja DEK bazy)
5. Budowa `AppState`, rejestracja tras Poem, start serwera HTTP

## Stan (`AppState`)

```rust
pub struct AppState {
    pub key_manager: Arc<Mutex<KeyManager<PlainFileMkProvider>>>,
    pub store: EphemeralStoreManager,
    pub db: Arc<DataManager<PlainFileMkProvider>>,
}
```

- **`key_manager`** — długoterminowe klucze serwera: X25519, ML-KEM-1024, Ed25519, ML-DSA-87;
   dostęp przez `Mutex`; używane do deszyfrowania żądań (tryb Shake) i podpisywania odpowiedzi
- **`store`** — pamięciowy cache TTL oparty na `BTreeMap` z automatycznym wygasaniem i zerowaniem 
   wartości przy dropie; używany do kluczy sesji, tokenów JWT, liczników rate limitingu, 
   hashy anti-replay i kluczy deszyfrowania wiadomości
- **`db`** — `DataManager` opakowujący połączenie PostgreSQL; obsługuje szyfrowanie kopertowe 
   blobów DB przy użyciu zarządzanego przez serwer DEK

## Trasy API

Wszystkie trasy owinięte są w `GuardMiddleware` (zewnętrzna) oraz trasową `CryptoMiddleware`.

| Metoda | Ścieżka          | Tryb krypto | Tryb auth      | Opis                                         |
|--------|------------------|-------------|----------------|----------------------------------------------|
| GET    | `/`                     | —           | —              | Powitanie                                    |
| GET    | `/health`               | —           | —              | Health check (status reapera i rotacji MK)   |
| POST   | `/shake`                | Shake       | KeysInHeaders  | Wymiana kluczy sesji                         |
| POST   | `/user/register/start`  | Session     | KeysInHeaders  | Rejestracja OPAQUE — faza 1                   |
| POST   | `/user/register/finish` | Session     | KeysInHeaders  | Rejestracja OPAQUE — faza 2                   |
| POST   | `/user/login/start`     | Session     | LoginByHandler | Logowanie OPAQUE — faza 1                     |
| POST   | `/user/login/finish`    | Session     | LoginByHandler | Logowanie OPAQUE — faza 2 (JWT + DEK)        |
| POST   | `/user/revoke`          | Session     | KeysInHeaders  | Usunięcie konta przez capability (bez logowania) |
| POST   | `/user/delete`          | Session     | JwtUser        | Usunięcie konta przez zalogowanego użytkownika |
| POST   | `/msg/send`             | Session     | KeysInHeaders  | Wysłanie wiadomości (anonimowe, + PoW)       |
| POST   | `/msg/fetch`            | Session     | KeysInHeaders  | Pobranie i usunięcie oczekujących wiadomości |

---

## Warstwa middleware

Każde żądanie przechodzi przez dwie warstwy middleware:

### GuardMiddleware (zewnętrzna)

Stosowana globalnie do wszystkich tras. Działa **przed** jakimkolwiek przetwarzaniem kryptograficznym.

1. **Rate limiting pre-replay per IP** — sprawdza klucz blokady per IP w `EphemeralStore`; jeśli zablokowany → `429 Too Many Requests`
2. **Kontrola rozmiaru ciała** — odrzuca ciała powyżej 1 MB
3. **Kontrola rozmiaru nagłówków** — odrzuca łączne dane nagłówków powyżej 1 MB
4. **Inkrementacja licznika pre-replay** — zwiększa licznik niepowodzeń per IP (okno: 10s); 
    aktywuje wykładnicze wycofanie po przekroczeniu progu (200 trafień):
   ```
   backoff = min(5s × 2^(hits − 200), 60s)
   ```
5. **Kontrola anti-replay** — oblicza `SHA256(raw_body_bytes)`, wywołuje `store.set_if_absent` z TTL = 600s;
    jeśli hash już istnieje → `400 replay_detected`
6. Przechowuje surowe ciało w rozszerzeniach żądania jako `CipherBody` dla `CryptoMiddleware`

### CryptoMiddleware (per trasa)

Każda trasa ma własną instancję skonfigurowaną przez `CryptoCfg` z `CryptoMode` i `AuthMode`.

Wywołuje `build_crypto_context`, który:
1. Wyodrębnia wszystkie nagłówki (małe litery)
2. Odszyfrowuje ciało zgodnie z `CryptoMode`
3. Parsuje odszyfrowane ciało JSON
4. Waliduje nagłówek `ts` (timestamp): musi być w granicach ±60s od zegara serwera
5. Weryfikuje podwójny podpis (Ed25519 + ML-DSA-87) nad surowymi bajtami odszyfrowanego JSON
6. Stosuje `AuthMode` do wypełnienia `ctx.user`
7. Wstrzykuje `CryptoContext` w rozszerzenia żądania jako `CryptoReq`

---

## Warstwa transportowa

### Tryby krypto

#### Tryb Shake (`CryptoMode::Shake`)

Używany dla `/shake` i pierwszej wiadomości sesji.

- Klient wysyła **efemeryczne** klucze publiczne X25519 + ML-KEM-1024 w nagłówkach żądania (`key-x`, `key-k`) 
  wraz z kluczami podpisującymi (`key-ed`, `key-dili`)
- Serwer używa tych efemerycznych kluczy klienta oraz własnych długoterminowych kluczy prywatnych
  (z `KeyManager`) do uzgodnienia klucza Kyberbox i odszyfrowania ciała
- TTL sesji Shake: **60 sekund**
- Odpowiedź zawiera nowe pary kluczy sesji (`key-x`, `key-k`) do kolejnych żądań w trybie Session

#### Tryb Session (`CryptoMode::Session`)

Używany dla wszystkich uwierzytelnionych endpointów po początkowym Shake.

- Klient wysyła wcześniej otrzymane klucze publiczne sesji w nagłówkach (`ses-x`, `ses-k`)
- Serwer odczytuje odpowiednie prywatne klucze sesji z `EphemeralStore` (klucz: hex klucza publicznego)
- Kyberbox-odszyfrowuje ciało przy użyciu pobranych par kluczy sesji
- TTL sesji: **120 sekund**
- Odpowiedź ponownie zawiera nowe pary kluczy sesji, przedłużając sesję

### Tryby autentykacji

| Tryb             | Działanie                                                                                                                                                                                         |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `KeysInHeaders`  | Wyodrębnia klucze publiczne klienta z nagłówków (`key-ed`, `key-dili`); `ctx.user` ma wartość `None`                                                                                              |
| `LoginByHandler` | Odczytuje `handler` z odszyfrowanego ciała, ładuje `UserRecord` z DB; `ctx.user` jest ustawiony. Hasła **nie** weryfikuje się tutaj — robi to przepływ OPAQUE w handlerze logowania; serwer nigdy nie widzi hasła ani jego hasha |
| `JwtUser`        | Odczytuje pole `token` z odszyfrowanego ciała (JWT szesnastkowo zakodowany), waliduje podpis HS256, wywołuje `store.take` (jednorazowe), ładuje użytkownika po user_id; `ctx.user` jest ustawiony |

### Nagłówki żądania (cleartext HTTP)

| Nagłówek | Opis |
|----------|------|
| `key-x`  | Efemeryczny klucz publiczny X25519 klienta (hex) — do deszyfrowania przez serwer |
| `key-k`  | Efemeryczny klucz publiczny ML-KEM-1024 klienta (hex) — do deszyfrowania przez serwer |
| `seed`   | Zaszyfrowane ziarno KEM |
| `data`   | Blob zaszyfrowanych nagłówków aplikacyjnych (KyberBox) |
| `ses-x`  | Losowy identyfikator sesji X25519 (hex) — lookup klucza prywatnego w EphemeralStore; tylko tryb Session |
| `ses-k`  | Losowy identyfikator sesji ML-KEM-1024 (hex) — lookup klucza prywatnego w EphemeralStore; tylko tryb Session |

Pola `key-ed`, `key-dili`, `sig-ed`, `sig-dili` przekazywane są w **zaszyfrowanych nagłówkach aplikacyjnych** (`data`), nie w cleartext. Pole `timestamp` przekazywane jest w **zaszyfrowanym ciele JSON**. Pole `token` (JWT hex) przekazywane jest w ciele (dotyczy wyłącznie trybu `JwtUser`).

### Nagłówki odpowiedzi

Po pomyślnym przetworzeniu `reply_ok` / `reply_ok_authed` generuje odpowiedź:

1. Generuje nowe pary kluczy sesji X25519 + ML-KEM-1024 oraz losowe identyfikatory `session_x_id`, `session_k_id` (po 32 losowe bajty każdy); przechowuje klucze prywatne w `EphemeralStore` pod tymi identyfikatorami z TTL sesji
2. Umieszcza identyfikatory (`ses-x`, `ses-k`) w nagłówkach JSON szyfrowanych przez KyberBox — klient odczyta je po deszyfrowaniu i odeśle w nagłówkach kolejnego żądania
3. Podwójnie podpisuje zaszyfrowane ciało odpowiedzi kluczami Ed25519 + ML-DSA-87 serwera
4. Dopełnia ciało (do bloku 32–64 KB) i nagłówki (do bloku 4–8 KB) w celu ukrycia rozmiarów
5. Ustawia cleartext nagłówki HTTP odpowiedzi: `sig-ed`, `sig-dili`, `data` (blob zaszyfrowanych nagłówków), `seed` (zaszyfrowane ziarno KEM), `key-x` (klucz publiczny X25519 nowej sesji — klient szyfruje do niego kolejne żądanie), `key-k` (klucz publiczny ML-KEM-1024 nowej sesji)

### JWT

- Algorytm: HS256
- Pole `sub`: `hex(HMAC-SHA256(user_id_bytes, random_seed_bytes))` — nieprzejrzysty identyfikator, 
  niepowiązany bezpośrednio z handlerem
- Token przechowywany w `EphemeralStore` pod wartością HMAC `sub` z `session_ttl`
- Token jest **jednorazowy** — `get_user_from_token` używa `store.take` (usuwa po pierwszym użyciu)
- Token jest szesnastkowo zakodowany przed umieszczeniem w ciele JSON odpowiedzi (pole `tok_hex`)

### Rate limiting (warstwa transportowa)

Wszystkie liczniki przechowywane w `EphemeralStoreManager`.

#### Login (`/user/login/start`)

| Parametr                           | Wartość                       |
|------------------------------------|-------------------------------|
| Okno niepowodzeń                   | 15 minut                      |
| Maksimum niepowodzeń przed blokadą | 5                             |
| Bazowe wycofanie                   | 30 sekund                     |
| Formuła wycofania                  | `30s × 2^(niepowodzenia − 1)` |
| Maksymalne wycofanie               | 15 minut                      |

Klucze store: `login:fail:{handler}`, `login:lock:{handler}`

#### Rejestracja (`/user/register/start`)

| Parametr                           | Wartość   |
|------------------------------------|-----------|
| Okno niepowodzeń                   | 1 godzina |
| Maksimum niepowodzeń przed blokadą | 3         |
| Czas blokady                       | 1 godzina |

Niepowodzeniem przy rejestracji jest próba zajęcia już istniejącego handlera. Sukces zeruje liczniki.

Klucze store: `reg:fail:{handler}`, `reg:lock:{handler}`

---

## Baza danych

### Schemat

#### Tabela `users`

| Kolumna         | Typ        | Opis                                                                       |
|-----------------|------------|----------------------------------------------------------------------------|
| `id`                | `BYTEA` PK | Deterministycznie zaszyfrowany UUID v5 znormalizowanego handlera           |
| `opaque_record`     | `BYTEA`    | Rekord OPAQUE (envelope), zaszyfrowany DEK serwera                         |
| `ed_key`            | `BYTEA`    | Klucz publiczny Ed25519 klienta (surowe bajty), zaszyfrowany DEK serwera   |
| `dili_key`          | `BYTEA`    | Klucz publiczny ML-DSA-87 klienta (surowe bajty), zaszyfrowany DEK serwera |
| `dek`               | `BYTEA`    | DEK po stronie klienta (string hex), zaszyfrowany DEK serwera              |
| `delete_token_hash` | `BYTEA`    | `SHA256(remote_delete_capability)` — klucz wyszukiwania przy `/user/revoke` (nie szyfrowany DEK) |

#### Tabela `messages`

| Kolumna      | Typ                        | Opis                                                                               |
|--------------|----------------------------|------------------------------------------------------------------------------------|
| `id`         | `BIGINT` auto-increment PK | ID wiadomości                                                                      |
| `mailbox`    | `BYTEA`                    | Adres skrzynki pocztowej (16 lub 32 bajty)                                         |
| `content`    | `BYTEA`                    | Zaszyfrowany blob wiadomości (`ver(1) \| nonce(12) \| AES-256-GCM-SIV ciphertext`) |
| `expires_at` | `TIMESTAMPTZ`              | Czas wygaśnięcia (TTL = 24 godziny od wstawienia)                                  |

### Ścieżka wyszukiwania użytkownika

```
string handlera
  → normalizacja (trim + małe litery)
  → UUID v5(db_namespace, znormalizowany_handler)
  → id_enc: AES-256-GCM-SIV(uuid_bytes, db_dek, nonce=HKDF(uuid, dek, label), aad="user-idenc/v1")
  → wyszukiwanie PK w tabeli users
```

ID użytkowników są szyfrowane **deterministycznie** — nonce wyprowadzany przez
`HKDF(uuid_bytes, key=db_dek, info=UIDENC_NONCE_LABEL)` — dzięki czemu ten sam handler 
zawsze mapuje się na ten sam szyfrogram. Umożliwia to indeksowane wyszukiwanie PK bez 
przechowywania jawnych identyfikatorów. Kompromisem jest obserwowalność równości 
ID użytkowników między snapshotami DB.

### Szyfrowanie pól użytkownika

Każde pole użytkownika w DB jest indywidualnie zapieczętowane pod DEK serwera przez 
`DataManager::encrypt_db_blob` / `decrypt_db_blob`. Każde pole używa osobnej stałej AAD:

| Pole            | AAD                       |
|-----------------|---------------------------|
| `opaque_record` | `"user-opaque-record/v1"` |
| `ed_key`        | `"user-ed-key/v1"`        |
| `dili_key`      | `"user-dili-key/v1"`      |
| `dek`           | `"user-dek/v1"`           |

### Szyfrowanie wiadomości

Wiadomości używają **losowego klucza per wiadomość** (`random_32()`) zamiast globalnego DEK bazy:

1. Przy `add_message`: generuje losowy `msg_key`, zapieczętowuje treść przez 
  `AES-256-GCM-SIV(content, msg_key, AAD="message-content/v1" || mailbox_bytes)`,
  przechowuje zaszyfrowany blob w DB; zapisuje `msg_key` w `EphemeralStore` pod
  kluczem `message_id.to_string()` z TTL = 24h
2. Przy `get_messages`: pobiera i **usuwa** wiersze w jednej transakcji `SELECT FOR UPDATE SKIP LOCKED` + `DELETE`;
  dla każdego wiersza wywołuje `store.take(message_id)` w celu pobrania i usunięcia klucza; odszyfrowuje blob

**Konsekwencja**: restart procesu serwera niszczy wszystkie klucze wiadomości w `EphemeralStore`, 
a przechowywane wiadomości stają się trwale nieodszyfrowalne (efemeryczna forward-secrecy klucza na poziomie relay).
Serwer nie może odczytać treści wiadomości nawet podczas normalnej pracy, ponieważ treść 
jest szyfrowana przez klienta przed dotarciem do serwera.

### Atomowe jednorazowe pobieranie wiadomości

Fetch działa wewnątrz transakcji DB z `SELECT FOR UPDATE SKIP LOCKED`:
- Tylko jeden jednoczesny fetcher może przejąć wiadomości danej skrzynki
- Wszystkie pobrane wiadomości są usuwane w ramach tej samej transakcji
- Wiadomości po `expires_at` są filtrowane przed selekcją
- Zwracane do klienta jako tablica szesnastkowo zakodowanych blobów

---

## Szczegóły handlerów API

### `GET /`

Brak przetwarzania kryptograficznego. Zwraca:
```json
{"message": "Welcome to Lithium, real private messenger"}
```

### `POST /shake`

Wykonuje wymianę kluczy w trybie Shake. Sam handler nic nie robi poza wywołaniem
`reply_ok`. Jego jedynym celem jest dostarczenie klientowi nowych par kluczy sesji 
(`key-x`, `key-k`) w odpowiedzi, używanych następnie do żądań w trybie Session.

### `POST /user/register/start` + `/user/register/finish`

Rejestracja OPAQUE jest dwufazowa — serwer **nigdy** nie widzi hasła ani jego hasha; zapisuje wyłącznie rekord OPAQUE.

Pola ciała (start): `handler`, `flow`, materiał OPAQUE (`RegistrationRequest`).
Pola ciała (finish): `handler`, `flow`, `opaque` (`RegistrationUpload`), `dek` — szesnastkowo zakodowany blob DEK klienta owinięty pod `export_key` z OPAQUE (nieprzejrzysty dla serwera; przechowywany zaszyfrowany i zwracany przy logowaniu).

Nagłówki żądania (poza transportowymi): `key-ed`, `key-dili` (długoterminowe klucze publiczne podpisujące klienta — serwer zapisuje je w `users`).

Działanie (faza finish):
1. Sprawdza limit rejestracji
2. Waliduje materiał OPAQUE i że `dek` jest poprawnym hex
3. Wywołuje `create_user` (zapisuje `opaque_record`, klucze, owinięty `dek`); jeśli handler już istnieje, inkrementuje licznik niepowodzeń i zwraca sukces (brak wycieku enumeracji handlerów)
4. Przy sukcesie: zeruje licznik

Odpowiedź: `{"msg": "Ok"}` (brak JWT przy rejestracji)

### `POST /user/login/start` + `/user/login/finish`

Logowanie OPAQUE jest dwufazowe. Tryb auth `LoginByHandler` ładuje `UserRecord` z DB przed uruchomieniem handlera.

Pola ciała (start): `handler`, `flow`, materiał OPAQUE (`CredentialRequest`).
Pola ciała (finish): `handler`, `flow`, `opaque` (`CredentialFinalization`).

Działanie (faza finish):
1. Sprawdza limit logowania
2. Kończy przepływ OPAQUE; niepowodzenie (złe hasło lub nieznany użytkownik) inkrementuje licznik i zwraca `401 invalid_credentials` — ten sam kod dla obu przypadków, bez wycieku istnienia użytkownika
3. Przy sukcesie: zeruje licznik, wystawia JWT przez `reply_ok_authed(session_ttl=120)`

Ciało odpowiedzi: `{"msg": "Ok", "dek": "<client_dek_hex>", "tok_hex": "<jwt_hex>"}`
oraz nowe pary kluczy sesji w nagłówkach odpowiedzi.

Pole `dek` zawiera owinięty DEK klienta zarejestrowany wcześniej — serwer przechowuje go i zwraca, lecz nigdy go nie używa.

### `POST /msg/send`

Auth `KeysInHeaders` — anonimowe, **bez** JWT (wysyłka nie wiąże się z tożsamością konta). Wymaga proof-of-work.

Pola ciała żądania:
- `mailbox` — szesnastkowo zakodowany adres skrzynki (po dekodowaniu musi mieć 16 lub 32 bajty)
- `content` — szesnastkowo zakodowany blob wiadomości (już zaszyfrowany przez klienta)
- `pow` — nonce proof-of-work; serwer liczy `challenge = SHA256("lithium/send-pow/v1" || u32_le(len(mailbox)) || mailbox || content)` i wymaga `leading_zero_bits(SHA256(challenge || u64_le(nonce))) >= LITHIUMS_SEND_POW_BITS` (domyślnie 18). Niespełniony PoW → `400 invalid_pow`.

Blob `content` jest dla serwera nieprzejrzysty — serwer owija go dodatkową warstwą szyfrowania (losowy klucz per wiadomość) i przechowuje w tabeli `messages`.

TTL: 24 godziny.

Odpowiedź: `{"msg": "Message sent"}`

### `POST /msg/fetch`

Używa auth `KeysInHeaders` (JWT nie jest wymagany — adres skrzynki służy jako capability).

Pola ciała żądania:
- `mailbox` — szesnastkowo zakodowany adres skrzynki (16 lub 32 bajty)

Zwraca wszystkie oczekujące, niewygasłe wiadomości dla skrzynki i atomowo je usuwa. Wiadomości zwracane są
jako tablica stringów hex (oryginalne blobj zaszyfrowane przez klienta).

Odpowiedź: `{"msg": "Ok", "data": ["<hex>", ...]}`

---

## Rotacja MK

Zadanie `MkRotator` działa w tle przez cały czas życia serwera:

- Budzi się co **30 sekund** i wywołuje `km.maybe_rotate_mk()`
- `maybe_rotate_mk()` sprawdza czas; jeśli minął `LITHIUM_MK_ROTATE_SECS` (domyślnie 3600s), rotuje master key
- Rotacja używa `PlainFileMkProvider`: klucze przechowywane jako zwykłe pliki w `LITHIUM_KEYS_DIR`
  (brak szyfrowania hasłem po stronie serwera — katalog kluczy musi być chroniony na poziomie OS/systemu plików)
- Rotacja MK **rewrapuje plik DEK** (ponownie szyfruje DEK pod nowym MK); istniejące dane w DB 
  **nie są ponownie szyfrowane**, ponieważ wartość DEK pozostaje niezmieniona
- `MkRotatorHandle` zawiera `watch::Sender<bool>` do płynnego zatrzymania

---

## Odpowiedzi błędów

Wszystkie błędy zwracają JSON:
```json
{"ok": false, "error": "<kod_błędu>"}
```

Błędy serwera (5xx) logowane na poziomie `ERROR` z pełnym łańcuchem źródła. Błędy klienta (4xx) logowane na poziomie `WARN`.

| Kod                       | Znaczenie                                    |
|---------------------------|----------------------------------------------|
| 400 `invalid_body`        | Nieprawidłowe ciało żądania                  |
| 400 `replay_detected`     | Dokładne powtórzenie ciała w oknie 600s      |
| 400 `body_too_large`      | Ciało przekracza 1 MB                        |
| 400 `headers_too_large`   | Łączne dane nagłówków przekraczają 1 MB      |
| 400 `invalid_dek`         | Pole `dek` nie jest poprawnym hex            |
| 400 `invalid_mailbox`     | Skrzynka nie ma 16 ani 32 bajtów             |
| 400 `invalid_content`     | Pole `content` nie jest poprawnym hex        |
| 400 `invalid_pow`         | Brak lub zły nonce proof-of-work (`/msg/send`) |
| 401 `invalid_credentials` | Logowanie OPAQUE nie powiodło się (złe hasło lub nieznany użytkownik) |
| 429 `try_later`           | Rate limiting (login/rejestracja/pre-replay) |
| 500 `internal_error`      | Nieoczekiwany błąd po stronie serwera        |
| 500 `db_error`            | Błąd operacji na bazie danych                |

---

## Model bezpieczeństwa

Serwer zaprojektowany jest jako **wrogie relay**:

- **Brak dostępu do plaintextu** — pola `content` wiadomości są E2E-szyfrowane przez 
  klienta przed dotarciem do serwera; serwer owija je dodatkową warstwą tymczasowego szyfrowania, ale nie może ich odczytać
- **Jednorazowe pobieranie wiadomości** — wiadomości są atomowo usuwane przy odbiorze; 
  serwer nie może odtwarzać wiadomości innemu klientowi
- **Efemeryczne klucze wiadomości** — klucze per wiadomość żyją tylko w pamięci (`EphemeralStoreManager`);
  restart serwera niszczy klucze dla oczekujących wiadomości
- **Anti-replay** — hash SHA256 ciała przechowywany 600s; okno timestampu ±60s zapobiega ponownemu użyciu żądania
- **Jednorazowy JWT** — tokeny są zużywane przy użyciu (`store.take`), uniemożliwiając replay uwierzytelnionych żądań
- **Nieprzejrzyste ID użytkownika** — pole `sub` w JWT to `HMAC-SHA256(user_id, random_seed)`, nie surowe ID
- **Izolacja pól DB** — każde pole użytkownika szyfrowane z osobną AAD; skompromitowany DEK z błędną AAD 
  nie pozwala odszyfrować innego pola
- **Dopełnianie rozmiaru** — ciała i nagłówki odpowiedzi dopełniane do rozmiarów bloków w celu ukrycia rzeczywistych długości danych
- **Brak materiału kluczowego po stronie serwera** — klucze prywatne klienta, plaintext treści wiadomości i session 
  plaintexts nigdy nie trafiają na serwer w niezaszyfrowanej postaci