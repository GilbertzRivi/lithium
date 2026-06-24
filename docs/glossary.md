# Słownik pojęć

Zwięzłe definicje terminów własnych Lithium. Głębsze opisy: protokół — [crypto-protocol.md](crypto-protocol.md), klucze — [key-hierarchy.md](key-hierarchy.md), KyberBox — [kyberbox.md](kyberbox.md), komendy IPC — [ipc-reference.md](ipc-reference.md).

**AEAD** — Authenticated Encryption with Associated Data. W Lithium zawsze AES-256-GCM-SIV.

**aPAKE** — asymmetric Password-Authenticated Key Exchange. Realizowany przez OPAQUE: klient dowodzi znajomości hasła bez ujawniania go serwerowi.

**Argon2id** — funkcja kosztowa (KSF) i derywacja z hasła; parametry 64 MiB, t=3, p=1. Używana w OPAQUE oraz do `password_root`.

**AuthMode** — tryb autoryzacji endpointu serwera: `KeysInHeaders` (klucze efemeryczne w nagłówkach, anonimowo), `LoginByHandler` (weryfikacja po `handler` w trakcie OPAQUE), `JwtUser` (tożsamość z JWT — tylko `/user/delete`).

**bootstrap** — klucze (X25519 + ML-KEM) wzięte z kodu zaproszenia `lci1:` i użyte do pierwszej wiadomości do kontaktu; usuwane z `self_state` po potwierdzeniu odbioru przez peera i ustanowieniu ratchetu. Też: tryb szyfrowania E2E używający tych kluczy.

**cid** — patrz **contact_id**.

**combined_root** — `HKDF(server_dek, salt=password_root, "lithium/user-provider/combined/v1")`; źródło `db_dek`. Tylko w RAM.

**commitment** — `SHA256("lithiumd/pair-commit/v1" || kod_zaproszenia)`. Jawny hash publikowany przed ujawnieniem kodu.

**commit-reveal** — jednostronny protokół parowania (4 komunikaty OOB), w którym twórca publikuje najpierw commitment, a kody są ujawniane w wymuszonej przez daemon kolejności. Sprzężony z krótkim **SAS** (patrz [design-decisions.md](design-decisions.md) #5).

**contact_id (cid)** — 32-bajtowy losowy identyfikator kontaktu, lokalny dla każdej strony (A ma `cid_a_b`, B ma `cid_b_a`).

**cover traffic** — ruch o stałej kadencji ukrywający czas i wolumen realnej komunikacji; realne wysyłki jadą w slotach, dummy wypełniają luki do self-loop cover-skrzynki. Odbiór jest automatyczny (brak manual fetch).

**CryptoMiddleware** — middleware serwera per trasa: deszyfruje ciało (Shake/Session), weryfikuje timestamp i dual-podpis, stosuje `AuthMode`.

**DataManager** — warstwa zaszyfrowanej bazy (SQLite u klienta, PostgreSQL na serwerze); `encrypt_db_blob`/`decrypt_db_blob` pod DEK z osobnym AAD per pole.

**db_dek** — DEK bazy danych, `HKDF(…, "lithium/db-dek/v1")`. U klienta wyprowadzany z `combined_root`, na serwerze z server MK.

**DEK (Data Encryption Key)** — klucz szyfrujący dane: w pliku `.keyf` losowy per plik (opakowany pod KEK), w bazie `db_dek`.

**EphemeralStore / EphemeralStoreManager** — magazyn w pamięci z TTL: klucze sesji transportowej, `msg_key`, JWT, liczniki rate-limit. Restart procesu czyści go w całości.

**export_key** — sekret wyprowadzany klient-side z OPAQUE, owijający `server_dek`.

**generacja (mailbox)** — licznik rotacji klucza nadawczego skrzynki. Fetch sprawdza okno `−2..+1` względem ostatnio widzianej generacji.

**GuardMiddleware** — zewnętrzne middleware serwera: rate-limit pre-replay per IP, limity rozmiaru (1 MiB ciało/nagłówki), anti-replay po `SHA256(ciało)`.

**handler** — nazwa użytkownika (login). Normalizowana (trim + małe litery); **nigdy** nie przechowywana jawnie na serwerze — mapowana na deterministyczne `id_enc`.

**harvest-now-decrypt-later** — model przeciwnika nagrywającego szyfrogram dziś, by odszyfrować go kwantowo w przyszłości. Powód hybrydy post-kwantowej.

**id_enc** — deterministyczny szyfrogram UUID v5 znormalizowanego handlera; klucz główny wiersza `users`. Umożliwia wyszukiwanie bez plaintextu handlera (kosztem obserwowalności równości).

**IPC** — kanał GUI ↔ daemon: JSON-lines po Unix socket (Linux/macOS) lub named pipe (Windows).

**JWT** — jednorazowy token HS256 wystawiany przy logowaniu OPAQUE; zużywany przy użyciu (`store.take`); wymagany wyłącznie przez `/user/delete`.

**KEK (Key Encryption Key)** — `HKDF(MK, salt_pliku, "kek/v1")`; opakowuje DEK wewnątrz pliku `.keyf`.

**KEM** — Key Encapsulation Mechanism; w Lithium hybryda X25519 + ML-KEM-1024.

**KeyManager** — zarządzanie plikami kluczy `.keyf` i rotacją Master Key.

**`.keyf`** — format pliku klucza z podwójnym opakowaniem: payload pod DEK, DEK pod KEK (z MK). Magic `KEYF`.

**KyberBox** — hybrydowa konstrukcja KEM-DEM: ML-KEM-1024 + X25519 → HKDF → AES-256-GCM-SIV dla `body` i `headers`. Patrz [kyberbox.md](kyberbox.md).

**lci1** — prefiks i binarny format kodu zaproszenia (hex po `lci1:`); wersja 1, 4361 bajtów danych.

**lithium_core / lithiumd / lithiumg / lithiums** — crate'y: wspólna biblioteka / daemon klienta / GUI / serwer relay.

**Master Key (MK)** — nadrzędny klucz szyfrujący pliki `.keyf`. U klienta opakowany hasłem danych; rotowany co 1 godzinę.

**mailbox (adres skrzynki)** — pseudolosowy 32-bajtowy adres na serwerze, liczony niezależnie przez nadawcę i odbiorcę z ECDH+HKDF. Serwer widzi tylko adres, nie wie kto z kim koresponduje.

**MkProvider** — wymienne źródło MK: `PlainFileMkProvider` (plik), `TpmMkProvider` (sealed w TPM), `ServerMkProvider` (enum dispatchujący na serwerze).

**MkRotator** — zadanie w tle budzące się co 30 s i rotujące MK po upływie interwału (domyślnie 3600 s).

**ML-DSA-87** (Dilithium) — post-kwantowy schemat podpisu; składnik dual-sign.

**ML-KEM-1024** (Kyber) — post-kwantowy KEM; składnik hybrydy szyfrowania.

**msg_id** — losowy 16-bajtowy identyfikator wiadomości w **podpisanym** nagłówku; deduplikacja przez ograniczenie `UNIQUE`.

**msg_key** — losowy klucz per wiadomość na serwerze (`EphemeralStore`, TTL 24 h). Restart serwera czyni zaległe wiadomości trwale nieodszyfrowalnymi.

**one-time fetch** — serwer kasuje wiadomość atomowo przy pierwszym pobraniu (`SELECT FOR UPDATE SKIP LOCKED` + `DELETE`).

**OPAQUE** — aPAKE (`opaque-ke 4.0.1`, ristretto255 + Argon2) używany do uwierzytelniania kont; rejestracja i logowanie są dwufazowe (`start`/`finish`).

**party transcript** — `HKDF` po konkatenacji 8 pól tożsamości strony (`cid`, `x_pub`, `ed_pub`, `dili_pub`, `k_pub`, 3 klucze mailbox); posortowane `t_a`/`t_b` wchodzą do `info` przy liczeniu SAS, wiążąc go z całą tożsamością obu stron.

**password_root** — `Argon2id(data_password, root.salt)`; hasłowy czynnik `db_dek`. Cache'owany w RAM.

**peer_set** — flaga kontaktu: druga strona zaakceptowała parowanie i wymieniono klucze — można wysyłać wiadomości.

**pinning (tożsamości serwera)** — klient przypina klucze publiczne serwera z pliku `server.identity`. Nie istnieje endpoint do ich pobrania — plik trafia do klienta zawsze kanałem out-of-band.

**PoW (proof-of-work)** — anty-spam na `/msg/send`: SHA-256 z wymaganą liczbą bitów zer wiodących (`LITHIUMS_SEND_POW_BITS`, domyślnie 18).

**prekey** — para kluczy (X25519 + ML-KEM) publikowana peerowi; pozwala wznowić komunikację po desynchronizacji. Usuwana po użyciu.

**prekey recover** — tryb szyfrowania E2E celujący w opublikowany prekey peera; odzyskuje kanał bez nowej wymiany zaproszeń.

**ProtocolManager** — klient transportu HTTP daemona do serwera; szyfruje KyberBoxem, dual-podpisuje, zarządza sesją, JWT i DEK.

**ratchet** — tryb E2E po pierwszej wiadomości zwrotnej: celuje w rotowane klucze `reply` (RX keyring) ostatnio odebranej wiadomości.

**relay (wrogie)** — serwer Lithium jako jawnie niegodny zaufania; przechowuje i przekazuje wyłącznie szyfrogram, nigdy nie widzi plaintextu.

**root.salt** — losowa, per-instalacja 32-bajtowa sól Argon2 dla `password_root`; plik `keystore/user/root.salt`.

**RX keyring (reply keys)** — rotowane klucze odbiorcze generowane przy każdym wysłaniu; peer szyfruje do nich kolejną wiadomość. Okno 32 sekwencji od `ack_seq`, starsze bezpiecznie kasowane.

**SAS (Short Authentication String)** — 6-symbolowy fingerprint (alfabet 64) do weryfikacji tożsamości kanałem głosowym/osobistym. Bezpieczny dzięki sprzężeniu z commit-reveal.

**server_dek** — losowy DEK przechowywany na serwerze (owinięty pod `export_key`, zwracany przy logowaniu); drugi czynnik `db_dek` klienta. Nigdy na dysku klienta.

**server.identity** — plik z kluczami publicznymi serwera (format TLV: x25519, ed25519, mlkem1024, mldsa87). Pinowany u klienta.

**Session (tryb)** — tryb transportu po Shake: klient używa kluczy sesji otrzymanych w poprzedniej odpowiedzi; TTL 120 s.

**Shake (tryb)** — tryb inicjalizacji sesji: efemeryczne klucze klienta + długoterminowe klucze serwera z `server.identity`; TTL 60 s.

**to_id** — `HKDF(x_pub || k_pub, "lithiumd/e2e-peer-kid/v1")`; identyfikator pary kluczy odbiorczych adresata w nagłówku `WireV1`.

**TPM sealing** — pieczętowanie Master Key serwera w TPM jako obiekt KEYEDHASH pod parentem ECC P-256 derywowanym z owner seed (parent nigdy nie persystowany).

**two-factor DEK** — `db_dek` wymaga jednocześnie `password_root` (z hasła) i `server_dek` (z serwera); żaden czynnik sam nie wystarcza.

**WireV1** — binarny format wiadomości E2E (magic `LM1`): `to_id`, efemeryczny `from_x_pub`, `seed` (ML-KEM), `enc_headers`, `enc_body`.
