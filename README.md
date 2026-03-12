# Lithium

Post-kwantowy komunikator E2E z jawnie niegodnym zaufania serwerem. Serwer nigdy nie widzi plaintextu — 
przechowuje i przekazuje wyłącznie szyfrogramy. Utrata materiału kluczowego jest preferowana 
nad jakimikolwiek wektorami odzyskiwania.

## Kryptografia

Hybrydowa — klasyczna + post-kwantowa jednocześnie, dla bezpieczeństwa na wypadek złamania jednego ze schematów:

| Cel                     | Schemat                         |
|-------------------------|---------------------------------|
| Wymiana kluczy          | X25519 + ML-KEM-1024 (Kyberbox) |
| Szyfrowanie symetryczne | AES-256-GCM-SIV                 |
| Podpisy                 | Ed25519 + ML-DSA-87 (dual-sign) |
| Wyprowadzanie kluczy    | HKDF-SHA256                     |
| Hashowanie haseł        | Argon2id                        |

Każda operacja wymaga **obu** podpisów i **obu** komponentów wymiany kluczy — kompromis jednego algorytmu nie wystarcza.

---

## Architektura

```
┌─────────────────────────────────────┐
│  lithiumg  (GUI — eframe/egui)      │
│  Interfejs użytkownika              │
└────────────────┬────────────────────┘
                 │ JSON-lines
                 │ Unix socket / Windows named pipe
┌────────────────▼────────────────────┐
│  lithiumd  (daemon klienta)         │
│  Klucze prywatne, SQLite, krypto    │
└────────────────┬────────────────────┘
                 │ HTTPS
                 │ Kyberbox (X25519 + ML-KEM-1024)
┌────────────────▼────────────────────┐
│  lithiums  (serwer relay)           │
│  PostgreSQL, tylko szyfrogramy      │
└─────────────────────────────────────┘

lithium_core — wspólna biblioteka krypto, kluczy i typów sekretnych
  (używana przez lithiumd i lithiums)
```

### Crates

| Crate                                    | Rola                                                                      |
|------------------------------------------|---------------------------------------------------------------------------|
| [`lithium_core`](lithium_core/README.md) | Wspólna biblioteka: kryptografia, zarządzanie kluczami, typy sekretne, DB |
| [`lithiumd`](lithiumd/README.md)         | Daemon klienta: klucze prywatne, E2E, SQLite, IPC, komunikacja z serwerem |
| [`lithiumg`](lithiumg/README.md)         | GUI: eframe/egui, komunikuje się z daemonem przez IPC                     |
| [`lithiums`](lithiums/README.md)         | Serwer relay: Poem, PostgreSQL, przekazuje szyfrogramy                    |

---

## Model zaufania

- **Serwer jest traktowany jak wróg.** Widzi tylko zaszyfrowane blobs — nie ma dostępu do treści wiadomości, kluczy prywatnych ani tożsamości rozmówców.
- **Daemon jest jedynym miejscem z kluczami prywatnymi.** GUI nie ma dostępu do materiału kluczowego.
- **Wiadomości są jednorazowe.** Serwer usuwa je po pierwszym pobraniu i nie może ich odtwarzać.
- **Brak odzyskiwania.** Utrata hasła do keystora = utrata dostępu. Nie istnieje reset ani backup po stronie serwera.

---

## Czym Lithium jawnie NIE jest

Projekt ma świadomie wąski zakres. Poniższe właściwości są **celowo nieobecne** — nie są błędami ani brakami do uzupełnienia:

- **Nie jest komunikatorem masowym.** Brak grup, kanałów, wątków, reakcji, statusów obecności, avatarów.
- **Nie ma recovery haseł ani kluczy.** Nie ma pytań pomocniczych, maila odzyskującego, kodu SMS ani żadnego 
  innego wektora reset. Utrata hasła do keystora = trwała utrata dostępu. To jest celowe.
- **Nie ma backupu po stronie serwera.** Serwer nie przechowuje historii wiadomości — wiadomości są usuwane 
  atomowo przy pierwszym pobraniu. Historia istnieje wyłącznie w lokalnym SQLite daemona.
- **Nie ma synchronizacji wielu urządzeń.** Jedno konto = jeden daemon na jednym urządzeniu. 
  Brak mechanizmu przenoszenia kluczy ani łączenia sesji.
- **Nie ma powiadomień push.** Model pull — klient sam odpytuje serwer o wiadomości. Brak APNs, FCM ani żadnej infrastruktury push.
- **Nie jest kompatybilny z Signal/Matrix/XMPP ani żadnym innym protokołem.** Własny protokół WireV1 i 
  własny format zaproszeń — celowo bez interoperacyjności.
- **Nie ma wersji webowej ani SaaS.** Wymaga lokalnie uruchomionego daemona. Brak hosted relay z gwarancjami dostępności.
- **Serwer nie weryfikuje tożsamości użytkowników.** Rejestracja nie wymaga telefonu, emaila ani żadnego
  identyfikatora zewnętrznego. Weryfikacja tożsamości leży w całości po stronie użytkowników (emoji fingerprint out-of-band).

---

## Przepływ danych

### Wysyłanie wiadomości

```
lithiumg
  → IPC: contact_send(contact_id, plaintext)
lithiumd
  → E2E encrypt (WireV1: X25519 + ML-KEM + AES-GCM-SIV + dual-sign)
  → HTTP POST /msg/send  (ciało Kyberbox-zaszyfrowane)
lithiums
  → wrap wiadomości losowym kluczem per-message
  → przechowuje w PostgreSQL (TTL 24h)
```

### Odbieranie wiadomości

```
lithiumg
  → IPC: contact_fetch(contact_id)
lithiumd
  → oblicza adres skrzynki (ECDH z kluczami mailbox)
  → HTTP POST /msg/fetch
lithiums
  → atomowo zwraca + usuwa wiadomości z DB
lithiumd
  → E2E decrypt (weryfikacja podpisu + deszyfrowanie)
  → zapisuje plaintext w SQLite
lithiumg
  → IPC: messages_list → wyświetla historię
```

### Zapraszanie kontaktu

```
Strona A: create_invite()  → kod lci1:HEX  (klucze publiczne A)
Strona B: accept_invite(kod_A, label) → my_code (klucze publiczne B)
Strona A: accept_invite(kod_B, contact_id=A)
→ obie strony mają peer_set=true → można pisać
```

Kod zaproszenia (`lci1:HEX`) zawiera wyłącznie klucze publiczne — żadnych danych prywatnych ani adresu serwera.

---

## Uruchomienie

### Wymagania

- Rust (stable, edycja 2024)
- PostgreSQL (dla `lithiums`)
- SQLite (wbudowany, dla `lithiumd`)

### Build

```bash
# Wszystkie crates
cargo build --release

# Tylko serwer
cargo build --release -p lithiums

# Tylko daemon + GUI
cargo build --release -p lithiumd -p lithiumg
```

### Testy

```bash
cargo test
cargo test -p lithium_core
```

### Lint / Format

```bash
cargo clippy -- -D warnings
cargo fmt
```

### Konfiguracja serwera (`lithiums`)

```bash
export DATABASE_URL=postgres://user:pass@localhost/lithium
export LITHIUM_KEYS_DIR=/var/lib/lithiums/keys
export LITHIUM_BIND=0.0.0.0:4108          # opcjonalnie
export LITHIUM_SERVER_NAME=default         # opcjonalnie
export LITHIUM_MK_ROTATE_SECS=3600        # opcjonalnie
lithiums
```

Przy pierwszym uruchomieniu serwer generuje klucze w `LITHIUM_KEYS_DIR`. Publiczne klucze serwera muszą zostać przekazane do konfiguracji daemona:

```bash
# Odczytaj klucze publiczne serwera i ustaw w środowisku daemona:
export SERVER_X25519=<hex>
export SERVER_KYBER=<hex>
export SERVER_ED25519=<hex>
export SERVER_DILITHIUM=<hex>
```

### Konfiguracja daemona (`lithiumd`)

```bash
export SERVER_X25519=<hex 32B>
export SERVER_KYBER=<hex 1568B>
export SERVER_ED25519=<hex 32B>
export SERVER_DILITHIUM=<hex 2592B>
export LITHIUMD_BASE_URL=https://relay.example.com
export LITHIUMD_DATA_DIR=/home/user/.local/share/lithiumd  # opcjonalnie
lithiumd
```

### GUI (`lithiumg`)

```bash
# Daemon musi być uruchomiony
lithiumg
```

Pierwsze uruchomienie przeprowadzi przez konfigurację:
1. Ustaw hasło do keystora (szyfruje klucze prywatne na dysku)
2. Podaj handler (nazwa konta) i hasło do konta serwera
3. Zarejestruj profil na serwerze

---

## Rotacja kluczy głównych (MK)

Oba serwer i daemon rotują master key co godzinę (domyślnie). Rotacja **rewrapuje DEK** — ponownie szyfruje
klucz bazy pod nowym MK, bez ponownego szyfrowania danych. Zadanie `MkRotator` sprawdza warunek co 30 sekund.

---

## Bezpieczeństwo — właściwości systemu

| Właściwość                                 | Mechanizm                                                                                                                                                                                                                        |
|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **PQC** — odporność post-kwantowa          | ML-KEM-1024 + ML-DSA-87 równolegle z X25519 + Ed25519; złamanie jednej grupy algorytmów nie wystarcza do skompromitowania systemu                                                                                                |
| **FS E2E per wiadomość** — ratchet         | Każda wiadomość WireV1 zawiera świeże efemeryczne klucze X25519 + ML-KEM-1024 (pole `reply`); odbiorca usuwa stare klucze prywatne po potwierdzeniu (ack) — kompromis klucza bieżącego nie ujawnia treści poprzednich wiadomości |
| **FS E2E per generację** — rotacja mailbox | Klucze skrzynki (mailbox) rotują co 32 wiadomości; stare klucze prywatne nadawcy są usuwane — dodatkowa granica FS niezależna od ratchetu                                                                                        |
| **FS transportu** — forward secrecy sesji  | Klient generuje efemeryczne klucze X25519 + ML-KEM per żądanie (tryb Shake); klucze sesji TTL 60–120s; wygaśnięcie sesji uniemożliwia odszyfrowanie wcześniejszego ruchu                                                         |
| **PCS** — post-compromise security         | Rotacja kluczy mailbox i mechanizm prekey recovery pozwalają odzyskać bezpieczeństwo po kompromisie stanu; atakujący traci dostęp po wymianie kolejnych kluczy                                                                   |
| Jednorazowe wiadomości                     | Serwer usuwa wiadomości atomowo przy pierwszym pobraniu; nie może ich odtworzyć ani przekazać ponownie                                                                                                                           |
| Anti-replay                                | SHA256(body) przechowywany 600s na serwerze (`set_if_absent`); timestamp żądania walidowany ±60s                                                                                                                                 |
| Ochrona przed enumeracją handlerów         | Nieudana rejestracja (zajęty handler) zwraca sukces — brak rozróżnialnej odpowiedzi                                                                                                                                              |
| Izolacja pól DB                            | Każde pole użytkownika szyfrowane z osobną domeną AAD; błędna AAD → błąd deszyfrowania                                                                                                                                           |
| Padding rozmiaru                           | Ciała dopełniane do bloków 32–64 KB, nagłówki do 4–8 KB — ukrywa długość wiadomości i typ operacji                                                                                                                               |
| Weryfikacja tożsamości                     | Emoji out-of-band (fingerprint ECDH kluczy kontaktu) — ochrona przed MITM przy wymianie zaproszeń                                                                                                                                |
| Jednorazowy JWT                            | Token zużywany przy użyciu (`store.take`) — nie można użyć przechwyconego tokenu ponownie                                                                                                                                        |
| Brak odzyskiwania po stronie serwera       | Serwer nie przechowuje ani nie zna żadnego materiału kluczowego klienta                                                                                                                                                          |

---

## Dokumentacja crates

Szczegółowa dokumentacja każdego komponentu w odpowiednim katalogu:

- [`lithium_core/README.md`](lithium_core/README.md) — kryptografia, typy sekretne, zarządzanie kluczami, format plików klucza
- [`lithiumd/README.md`](lithiumd/README.md) — IPC, E2E WireV1, mailbox, zaproszenia, SQLite, PasswordFileMkProvider
- [`lithiumg/README.md`](lithiumg/README.md) — GUI, maszyna stanów ekranów, model wątków, protokół IPC
- [`lithiums/README.md`](lithiums/README.md) — REST API, middleware, transport Shake/Session, schemat PostgreSQL