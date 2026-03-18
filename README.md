# Lithium

**Post-kwantowy komunikator szyfrowany end-to-end, zaprojektowany dla środowisk o wysokich wymaganiach bezpieczeństwa.**

Lithium nie jest komunikatorem konsumenckim. Powstał dla organizacji i użytkowników, którzy nie mogą sobie pozwolić na to, żeby treść ich komunikacji była dostępna dla kogokolwiek poza bezpośrednimi rozmówcami — włącznie z operatorem, dostawcą infrastruktury czy sądem wydającym nakaz.

> **Priorytet projektowy:** Poufność treści jest ważniejsza od wygody. Jeśli te dwie wartości wchodzą w kolizję, Lithium wybiera poufność.

---

## Dla kogo jest Lithium

Lithium jest przeznaczony dla środowisk, w których:

- serwer, operator lub infrastruktura mogą być **monitorowane, przejęte lub prawnie zmuszone do współpracy**,
- klasyczne komunikatory (nawet te szyfrowane) są nieakceptowalne z uwagi na **zaufanie do operatora**,
- organizacja potrzebuje komunikatora, który **matematycznie uniemożliwia ujawnienie treści** przez dostawcę usługi,
- istnieje realne ryzyko, że **dysk klienta zostanie przejęty** przez przeciwnika,
- wymogi regulacyjne lub operacyjne wymagają **minimalnej retencji** danych i braku możliwości odtworzenia historii przez operatora.

Przykładowe grupy odbiorców: kancelarie prawne, firmy zajmujące się negocjacjami i fuzjami, organizacje dziennikarskie i NGO działające w trudnych środowiskach, instytucje finansowe wymagające poufności komunikacji wewnętrznej.

---

## Kluczowe właściwości

### Operator matematycznie nie może ujawnić treści

Serwer Lithium jest traktowany jak wrogi relay. Przechowuje i przekazuje wyłącznie zaszyfrowane dane. Nie ma dostępu do:
- treści wiadomości,
- kluczy prywatnych użytkowników,
- relacji między rozmówcami (adresy skrzynek są kryptograficznie pseudolosowe).

Nawet pod przymusem prawnym operator nie jest w stanie dostarczyć plaintextu — nie dlatego, że odmawia, ale dlatego, że **go nie ma**.

### Odporność post-kwantowa

Wszystkie operacje kryptograficzne są hybrydowe: wykonywane jednocześnie klasycznym i post-kwantowym algorytmem. Złamanie jednego z nich nie narusza bezpieczeństwa systemu — oba muszą zostać złamane jednocześnie.

| Cel                    | Algorytmy                           |
|------------------------|-------------------------------------|
| Wymiana kluczy         | X25519 + ML-KEM-1024 (NIST PQC)    |
| Szyfrowanie symetryczne| AES-256-GCM-SIV                     |
| Podpisy cyfrowe        | Ed25519 + ML-DSA-87 (NIST PQC)     |
| Wyprowadzanie kluczy   | HKDF-SHA256                         |
| Hashowanie haseł       | Argon2id                            |

Algorytmy post-kwantowe (ML-KEM-1024, ML-DSA-87) są standardami zatwierdzonymi przez NIST w 2024 roku jako docelowe dla środowisk wymagających odporności na komputery kwantowe.

### Forward secrecy — przeszłość jest bezpieczna nawet po ujawnieniu klucza

- **Per wiadomość:** każda wiadomość zawiera świeże efemeryczne klucze. Ujawnienie klucza bieżącego nie pozwala odszyfrować poprzednich wiadomości.
- **Per generację:** klucze skrzynki rotują co 32 wiadomości; stare klucze prywatne są bezpiecznie kasowane.
- **Transport:** klucze sesji transportowej mają TTL 60–120 sekund; przejęcie sesji nie pozwala odszyfrować wcześniejszego ruchu.

### Dwuczynnikowa ochrona lokalnych danych

Odszyfrowanie danych przechowywanych na urządzeniu wymaga jednocześnie:
1. hasła użytkownika (dane lokalne),
2. komponentu z serwera (DEK pobierany przy każdym logowaniu).

DEK (klucz szyfrowania danych) jest generowany losowo przez klienta podczas rejestracji — serwer go nie tworzy, nie zna i nie może odtworzyć. Klient wysyła go do serwera już zaszyfrowanego własnym hasłem i serwer przechowuje go jako nieprzejrzysty blob, zwracając go przy każdym logowaniu. Serwer jest tu wyłącznie nośnikiem — bez hasła klienta nie jest w stanie go użyć.

Przejęcie dysku urządzenia bez znajomości hasła **i** dostępu do serwera nie daje żadnego plaintextu. Jest to decyzja projektowa, nie ograniczenie.

### Unikalność kryptograficzna per instalacja

Każda instalacja daemona generuje własne materiały kryptograficzne niezależnie — klucze asymetryczne, seed master key, klucze mailbox — przy użyciu systemowego generatora liczb losowych (CSRNG). Nie istnieje żaden wspólny sekret ani seed instalacyjny. Dwie instalacje na dwóch urządzeniach nie mają żadnej kryptograficznej relacji, nawet jeśli należą do tego samego użytkownika.

### Pinowanie tożsamości serwera i ochrona przed podmianą

Tożsamość serwera — zestaw czterech kluczy publicznych (X25519, ML-KEM-1024, Ed25519, ML-DSA-87) — jest przechowywana jako plik binarny `server.identity` generowany przez serwer przy pierwszym uruchomieniu. Daemon klienta wczytuje ten plik i weryfikuje pod nim każdą odpowiedź serwera.

Konsekwencja: **dowolna zmiana kluczy serwera — czy to przez podmianę, czy ingerencję zewnętrzną — powoduje natychmiastowe i trwałe zerwanie komunikacji ze wszystkimi istniejącymi klientami.** Klient nie może się połączyć z serwerem, którego tożsamości nie rozpoznaje. Wznowienie wymaga świadomej decyzji po stronie użytkowników: ręcznego wgrania nowego pliku `server.identity`. Jest to celowe — podmiana kluczy serwera bez wiedzy użytkowników jest niemożliwa.

### Wiadomości jednorazowe

Wiadomości są usuwane z serwera atomowo przy pierwszym pobraniu. Serwer nie przechowuje historii. Historia istnieje wyłącznie w lokalnej bazie klienta, zaszyfrowanej per urządzenie.

### Weryfikacja tożsamości bez udziału serwera

Serwer nie jest źródłem zaufania. Tożsamość rozmówcy jest weryfikowana przez porównanie emoji fingerprint kanałem out-of-band (np. telefonicznie). Serwer nie może podrobić tożsamości żadnej ze stron.

---

## Architektura systemu

```
┌─────────────────────────────────────┐
│  lithiumg  (GUI — Linux / Windows)  │
│  Interfejs użytkownika              │
└────────────────┬────────────────────┘
                 │ JSON / Unix socket / Windows named pipe
                 │ (tylko lokalne połączenia)
┌────────────────▼────────────────────┐
│  lithiumd  (daemon klienta)         │
│  Klucze prywatne · SQLite · krypto  │
│  Jedyne miejsce z plaintextem       │
└────────────────┬────────────────────┘
                 │ HTTPS
                 │ Kyberbox (X25519 + ML-KEM-1024)
                 │ dual-sign (Ed25519 + ML-DSA-87)
┌────────────────▼────────────────────┐
│  lithiums  (serwer relay)           │
│  PostgreSQL · tylko szyfrogramy     │
│  Nie widzi plaintextu               │
└─────────────────────────────────────┘
```

System składa się z czterech komponentów:

| Komponent        | Rola                                                                               |
|------------------|------------------------------------------------------------------------------------|
| `lithium_core`   | Biblioteka kryptograficzna — wspólna dla daemona i serwera                         |
| `lithiumd`       | Daemon klienta — przechowuje klucze, wykonuje szyfrowanie, wystawia IPC dla GUI    |
| `lithiumg`       | Interfejs graficzny — komunikuje się z daemonem, sam nie dotyka kluczy             |
| `lithiums`       | Serwer relay — przyjmuje i przekazuje zaszyfrowane wiadomości, PostgreSQL          |

### Izolacja kryptograficzna

Klucze prywatne i plaintext istnieją wyłącznie w `lithiumd` na urządzeniu użytkownika. GUI (`lithiumg`) komunikuje się z daemonem przez lokalny socket i nigdy nie ma dostępu do materiału kluczowego. Serwer (`lithiums`) widzi wyłącznie zaszyfrowane bloby — nie uczestniczy w żadnej operacji kryptograficznej E2E.

---

## Przepływ wiadomości

### Wysyłanie

```
Użytkownik wpisuje tekst w GUI
  → GUI wysyła IPC do daemona: contact_send(contact_id, plaintext)
  → daemon szyfruje: WireV1 (X25519 + ML-KEM + AES-256-GCM-SIV + dual-sign)
  → daemon wysyła zaszyfrowany blob przez HTTPS do serwera
  → serwer owija blob dodatkowym losowym kluczem per wiadomość
  → przechowuje w PostgreSQL (TTL 24h)
```

### Odbieranie

```
Użytkownik klika Fetch w GUI
  → GUI wysyła IPC do daemona: contact_fetch(contact_id)
  → daemon oblicza adres skrzynki (ECDH z kluczami mailbox)
  → daemon pobiera blobs z serwera przez HTTPS
  → serwer atomowo zwraca + usuwa wiadomości z bazy
  → daemon deszyfruje i weryfikuje podpisy
  → zapisuje plaintext w lokalnym SQLite
  → GUI wyświetla historię
```

### Dodawanie kontaktu (wymiana zaproszeń)

Parowanie odbywa się przez wymianę kodów zaproszenia (`lci1:HEX`) — poza serwerem, kanałem out-of-band (email, telefon, inne). Kod zaproszenia zawiera wyłącznie klucze publiczne — żadnych danych prywatnych.

```
Strona A: [New invite] → kod lci1:HEX (klucze publiczne A)
Strona B: wkleja kod A + [Add contact] → otrzymuje my_code (klucze publiczne B)
Strona A: wkleja kod B + [Reply]
→ obie strony mają peer_set=true → można pisać
```

Po wymianie obie strony weryfikują emoji fingerprint kanałem głosowym lub osobistym — dopiero to potwierdza, że nie doszło do ataku MITM.

---

## Właściwości bezpieczeństwa — zestawienie

| Właściwość                          | Mechanizm                                                                                               |
|-------------------------------------|---------------------------------------------------------------------------------------------------------|
| Odporność post-kwantowa             | ML-KEM-1024 + ML-DSA-87 równolegle z X25519 + Ed25519; oba algorytmy muszą być złamane jednocześnie   |
| Forward secrecy per wiadomość       | Świeże efemeryczne klucze X25519 + ML-KEM w każdej wiadomości (ratchet); stare klucze kasowane po ack  |
| Forward secrecy per generację       | Rotacja kluczy mailbox co 32 wiadomości; stare klucze prywatne nadawcy kasowane                         |
| Forward secrecy transportu          | Klucze sesji TTL 60–120s; efemeryczne klucze X25519 + ML-KEM per żądanie (tryb Shake)                  |
| Post-compromise security            | Rotacja kluczy mailbox i prekey recovery pozwalają odzyskać bezpieczeństwo po przejęciu stanu           |
| Brak plaintextu na serwerze         | Treść szyfrowana przez klienta zanim dotrze do serwera; serwer dokłada drugą warstwę, ale jej nie czyta |
| Jednorazowe wiadomości              | Atomowe usunięcie przy pierwszym pobraniu; serwer nie może ich odtworzyć                               |
| Efemeryczne klucze wiadomości       | Klucze per wiadomość żyją wyłącznie w pamięci serwera; restart serwera niszczy klucze                  |
| Ochrona przed enumeracją handlerów  | Próba zajęcia istniejącego loginu zwraca sukces — brak rozróżnialnej odpowiedzi                         |
| Anti-replay                         | SHA256(body) przechowywany 600s; timestamp żądania walidowany ±60s                                     |
| Jednorazowy JWT                     | Token zużywany przy użyciu — przejęty token nie może być odtworzony                                    |
| Izolacja pól bazy danych            | Każde pole szyfrowane z osobną domeną AAD; błędna AAD → błąd deszyfrowania                             |
| Padding rozmiaru                    | Ciała dopełniane do bloków 32–64 KB, nagłówki do 4–8 KB — ukrywa długość i typ operacji                |
| Weryfikacja tożsamości              | Emoji fingerprint out-of-band — MITM przy wymianie zaproszeń wykrywalny przez użytkowników             |
| Dwuczynnikowa ochrona lokalnych danych | Hasło + komponent serwerowy; przejęcie dysku bez hasła i serwera = brak dostępu                     |
| Zeroizacja pamięci                  | Wszystkie typy sekretne kasują pamięć przy zwolnieniu (`zeroize`); klucze nie pozostają w pamięci      |
| Atomowe operacje plikowe            | Zapis kluczy przez `tmp + rename + fsync`; przerwanie nie psuje stanu                                  |
| Crash-safe rotacja kluczy           | Niedokończona rotacja wykrywana i kończona przy starcie                                                 |
| Pinowanie tożsamości serwera        | Klient weryfikuje każdą odpowiedź pod kluczami z pliku `server.identity`; zmiana kluczy serwera zrywa połączenie ze wszystkimi klientami |
| Awaryjne usunięcie konta            | Przy rejestracji serwer generuje jednorazowy capability (32 bajty losowe); SHA-256 w DB; wystarczy do usunięcia konta bez logowania po utracie urządzenia |
| Unikalność per instalacja           | Wszystkie klucze i seedy generowane niezależnie z CSRNG per urządzenie; brak wspólnych sekretów instalacyjnych |
| DEK generowany przez klienta        | Klucz szyfrowania danych tworzony losowo przez klienta; wysyłany do serwera zaszyfrowany hasłem; serwer przechowuje nieprzejrzysty blob |

---

## Czym Lithium celowo NIE jest

Poniższe ograniczenia są **cechami projektu**, nie błędami. Wynikają wprost z modelu bezpieczeństwa.

- **Nie jest komunikatorem masowym.** Brak grup, kanałów, statusów obecności, reakcji, wątków, avatarów.
- **Nie ma odzyskiwania hasła.** Utrata hasła do keystora = trwała utrata dostępu. Nie istnieje żaden mechanizm resetu — ani mailowy, ani SMS, ani przez operatora. To jest celowe.
- **Nie przechowuje historii po stronie serwera.** Wiadomości są usuwane przy pobraniu. Historia istnieje wyłącznie lokalnie.
- **Nie obsługuje wielu urządzeń.** Jedno konto = jeden daemon na jednym urządzeniu. Brak synchronizacji między urządzeniami.
- **Nie ma powiadomień push.** Model pull — klient sam odpytuje serwer. Brak APNs, FCM, ani żadnej infrastruktury push.
- **Nie gwarantuje dostarczenia każdej wiadomości.** Serwer może odmawiać działania, gubić dane, wpływać na dostępność. Serwer nie jest zaufanym elementem — a to ma swoją cenę operacyjną.
- **Nie działa w pełni offline.** Odszyfrowanie lokalnych danych wymaga komponentu z serwera. Jest to celowe — utrata dostępu jest preferowana nad ryzyko odczytania danych po kradzieży urządzenia.
- **Nie ma interoperacyjności.** Własny protokół WireV1 i własny format zaproszeń — celowo bez kompatybilności z Signal, Matrix, XMPP ani innymi systemami.
- **Nie ma wersji webowej ani SaaS.** Wymaga lokalnie uruchomionego daemona. Operator nie jest w stanie udzielić gwarancji dostępności SaaS bez jednoczesnego naruszenia modelu zaufania.

---

## Wdrożenie

### Wymagania

- **Rust** (stable, edycja 2024) — do budowania ze źródeł
- **PostgreSQL** — dla serwera relay (`lithiums`)
- **SQLite** — wbudowany, dla daemona klienta (`lithiumd`)
- **Linux lub Windows** — klient i serwer

### Budowanie

```bash
# Wszystkie komponenty
cargo build --release

# Tylko serwer relay
cargo build --release -p lithiums

# Tylko klient (daemon + GUI)
cargo build --release -p lithiumd -p lithiumg
```

### Uruchomienie serwera relay

`lithiums` nasłuchuje na czystym HTTP. TLS terminuje reverse proxy (nginx, Caddy itp.) przed procesem serwera.

Docelowym środowiskiem deploymentu jest Docker Compose — cała konfiguracja serwera odbywa się przez zmienne środowiskowe, hasło do bazy podawane jest przez plik (Docker secret), a katalog kluczy montowany jako wolumin.

```bash
export DB_HOST=localhost
export DB_USER=lithium
export DB_PASSWORD_FILE=/run/secrets/db_password
export DB_NAME=lithium
export LITHIUM_KEYS_DIR=/var/lib/lithiums/keys
export LITHIUM_BIND=0.0.0.0
export LITHIUM_PORT=4108

lithiums
```

Przy pierwszym uruchomieniu serwer generuje własne klucze w `LITHIUM_KEYS_DIR` i zapisuje plik `server.identity` zawierający cztery klucze publiczne (X25519, ML-KEM-1024, Ed25519, ML-DSA-87) w formacie binarnym z magic bytes. Plik ten jest jedynym artefaktem dystrybucji tożsamości serwera — należy go przekazać użytkownikom kanałem out-of-band.

### Konfiguracja daemona klienta

```bash
export LITHIUMD_BASE_URL=https://relay.example.com
export LITHIUMD_SERVER_IDENTITY=/ścieżka/do/server.identity   # opcjonalnie; domyślnie: {data_dir}/server.identity

lithiumd
```

Daemon odczytuje tożsamość serwera z pliku `server.identity` — nie z env vars. Plik musi zostać dostarczony przez administratora serwera przed pierwszym połączeniem.

### Uruchomienie GUI

```bash
# Daemon musi być uruchomiony
lithiumg
```

Pierwsze uruchomienie GUI przeprowadza przez konfigurację:
1. Wgraj plik `server.identity` (weryfikacja tożsamości serwera)
2. Ustaw hasło do keystora (szyfruje klucze prywatne na dysku)
3. Podaj nazwę konta i hasło do konta serwera
4. Zarejestruj profil na serwerze — po rejestracji GUI wyświetla **capability do awaryjnego usunięcia konta** (patrz niżej); należy go zapisać

### Awaryjne zdalne usunięcie konta

Podczas rejestracji serwer generuje losowy 32-bajtowy token (`remote_delete_capability`) i zwraca go klientowi. W bazie danych przechowywany jest wyłącznie SHA-256 tego tokenu — serwer nie zna wartości capability w postaci jawnej.

Jeśli urządzenie zostanie utracone lub skradzione, użytkownik może usunąć swoje konto z serwera bez potrzeby logowania — wystarczy capability i dostęp do pliku `server.identity`:

```
GUI → [Emergency account removal] → wklej capability → [Remove]
```

Capability nie wymaga hasła ani aktywnej sesji. Nie da się go odtworzyć — utrata capability = trwały brak możliwości usunięcia konta przez właściciela. Interwencja administracyjna nie jest alternatywą: handlery nie są przechowywane w postaci jawnej — w bazie istnieje wyłącznie UUID v5 wyprowadzony z handlera, szyfrowany deterministycznie kluczem serwera. Operator nie jest w stanie zidentyfikować ani odszukać rekordu po handlerze, nazwie użytkownika ani żadnym innym jawnym identyfikatorze.

---

## Rotacja kluczy głównych

Daemon i serwer rotują master key co godzinę (domyślnie). Rotacja jest atomowa i crash-safe — niedokończona rotacja jest automatycznie wykrywana i kończona przy starcie. Rotacja rewrapuje klucze pod nowym master key bez ponownego szyfrowania danych w bazie.

---

## Podstawy kryptograficzne — biblioteki

| Biblioteka      | Wersja  | Rola                                     |
|-----------------|---------|------------------------------------------|
| `aes-gcm-siv`   | 0.11.1  | AES-256-GCM-SIV (AEAD)                  |
| `hkdf`          | 0.12    | HKDF-SHA256 (KDF)                        |
| `pqcrypto`      | 0.18.1  | ML-KEM-1024 (Kyber), ML-DSA-87 (Dilithium) |
| `ed25519-dalek` | 2.2.0   | Ed25519 (podpisy klasyczne)              |
| `x25519-dalek`  | 2.0.1   | X25519 (ECDH klasyczny)                  |
| `argon2`        | 0.5.3   | Argon2id (hasła, wrapping DEK)           |
| `zeroize`       | 1.8.2   | Zeroizacja pamięci przy Drop             |
| `secrecy`       | 0.10.3  | Typy sekretne (SecretBox)                |

Cały `lithium_core` ma `#![forbid(unsafe_code)]`.

---

## Model bezpieczeństwa — podsumowanie

Lithium zakłada, że:

- serwer jest lub może być wrogi, monitorowany albo prawnie zmuszony do współpracy,
- dysk klienta może zostać przejęty,
- operator nie jest i nie może być zaufanym podmiotem dla poufności treści.

W odpowiedzi na te założenia:

- serwer matematycznie nie jest w stanie odszyfrować treści wiadomości,
- operator nie uczestniczy w parowaniu użytkowników ani w weryfikacji tożsamości,
- kompromitacja serwera nie daje dostępu do historii wiadomości,
- kompromitacja dysku klienta bez hasła i bez serwera nie daje dostępu do danych,
- utrata materiału kluczowego prowadzi do utraty dostępu — nigdy do możliwości odzysku przez stronę trzecią.

**Lithium nie ma być wygodne. Ma być trudne do zdradzenia.**

---

## Dokumentacja techniczna

- [`docs/`](docs/index.md) — indeks dokumentacji (dla audytorów i integratorów)
  - [`docs/security-model.md`](docs/security-model.md) — model zaufania, priorytety, świadome kompromisy, klasyfikacja ustaleń audytowych
  - [`docs/crypto-protocol.md`](docs/crypto-protocol.md) — specyfikacja protokołu kryptograficznego: transport, E2E, mailbox, cykl życia kluczy
  - [`docs/ipc-reference.md`](docs/ipc-reference.md) — referencja protokołu IPC daemona
  - [`docs/kyberbox.md`](docs/kyberbox.md) — analiza bezpieczeństwa schematu KyberBox
- [`lithium_core/README.md`](lithium_core/README.md) — kryptografia, typy sekretne, zarządzanie kluczami
- [`lithiumd/README.md`](lithiumd/README.md) — daemon klienta: IPC, E2E, mailbox, SQLite
- [`lithiums/README.md`](lithiums/README.md) — serwer relay: REST API, middleware, transport, PostgreSQL
- [`lithiumg/README.md`](lithiumg/README.md) — GUI: maszyna stanów, model wątków