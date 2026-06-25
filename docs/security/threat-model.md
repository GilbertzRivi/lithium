# Model zagrożeń (zorientowany na przeciwnika)

Companion do [security-model.md](security-model.md), który opisuje model zaufania, priorytety i świadome kompromisy. Ten dokument podchodzi od strony **przeciwnika**: dla każdej klasy atakującego wylicza zdolności, obronę Lithium i ryzyko rezydualne. Mechanikę kryptograficzną opisuje [crypto-protocol.md](../protocol/crypto-protocol.md), a mapę kluczy [key-hierarchy.md](key-hierarchy.md).

## Aktywa chronione

1. **Treść wiadomości** (priorytet najwyższy)
2. **Graf społeczny** — kto z kim koresponduje
3. **Klucze i tożsamość per kontakt**
4. **Poświadczenie konta** (hasło) i lokalne dane w spoczynku
5. **Metadane** (czas, wolumen) — w mniejszym stopniu

## Klasy przeciwnika

### 1. Pasywny obserwator sieci

| | |
|---|---|
| **Zdolności** | Podsłuch ruchu klient–serwer: szyfrogram, czas, wolumen, adresy IP |
| **Obrona** | TLS (na proxy) + szyfrowanie transportu KyberBox + warstwa E2E; constant-rate cover traffic ukrywa czas i wolumen realnych wiadomości; padding ukrywa rozmiary |
| **Ryzyko rezydualne** | Fakt istnienia połączenia z relayem i zgrubny stan online/offline; IP klienta (brak wbudowanego Tora) |

### 2. Aktywny atakujący sieciowy / MITM

| | |
|---|---|
| **Zdolności** | Przechwycenie, modyfikacja, wstrzykiwanie, próby downgrade i replay |
| **Obrona** | Pinowana tożsamość serwera (`server.identity`); dual-podpis żądań i odpowiedzi; okno timestampu ±60 s; anti-replay po haszu ciała (600 s); kryptografia nie ufa TLS-owi (KyberBox do pinowanych kluczy). MITM przy parowaniu zamyka commit-reveal + SAS |
| **Ryzyko rezydualne** | DoS przez odcięcie ruchu (brak gwarancji dostarczenia — świadome); bootstrap `server.identity` musi przyjść kanałem out-of-band |

### 3. Złośliwy lub przejęty serwer relay (główny przeciwnik)

| | |
|---|---|
| **Zdolności** | Odczyt całego składowanego szyfrogramu; widzi adresy skrzynek + czas; może gubić, zmieniać kolejność, wstrzymywać, próbować re-injekcji/replay, kłamać o stanie, odmawiać usługi, próbować korelacji |
| **Obrona** | Nigdy nie ma kluczy E2E → nie czyta treści; adresy skrzynek pseudolosowe → nie linkuje kto-do-kogo; one-time fetch (atomowe usunięcie); klucze per wiadomość efemeryczne (restart → nieodszyfrowalne); deterministyczne `id_enc` ujawnia wyłącznie równość; dual-podpis → nie podrobi tożsamości peera ani się nie podszyje |
| **Ryzyko rezydualne** | Analiza metadanych skrzynek (czas/wolumen — łagodzona cover traffic); wstrzymanie/DoS (świadome); obserwowalność równości `id_enc` między snapshotami DB (świadomy kompromis); może gubić, ale nie fałszować |

### 4. Złodziej urządzenia — bez hasła danych

| | |
|---|---|
| **Zdolności** | Pełny obraz dysku, praca offline |
| **Obrona** | MK za `Argon2id(data_password, …)` (64 MiB, t=3); `db_dek` wymaga hasła **oraz** `server_dek`; pliki `.keyf` zaszyfrowane; katalog danych `0o700` |
| **Ryzyko rezydualne** | Offline brute-force słabego hasła (koszt Argon2; polityka min 12 znaków). `server_dek` to drugi czynnik |

### 5. Złodziej urządzenia — z hasłem danych, bez serwera

| | |
|---|---|
| **Zdolności** | Dysk + znajomość hasła danych, ale brak dostępu do serwera |
| **Obrona** | `db_dek` nadal wymaga `server_dek` (trzymanego przez serwer) → lokalna baza wiadomości/kontaktów pozostaje niedostępna offline |
| **Ryzyko rezydualne** | Jeśli atakujący ma też żywą sesję z serwerem (pełne przejęcie konta) → pełne dane. Dwuczynnik trzyma tylko bez współpracy serwera |

### 6. Złośliwy kontakt (peer)

| | |
|---|---|
| **Zdolności** | Sparowany kontakt wysyła spreparowane/zniekształcone wiadomości, próbuje korupcji stanu, replay, przejęcia slotu kontaktu |
| **Obrona** | Izolacja per kontakt; weryfikacja dual-podpisu (niepodrabialna per kontakt); dedup `msg_id` (UNIQUE); numery sekwencji rosną tylko w przód (brak regresji stanu); commit-reveal blokuje peer-takeover ustanowionego slotu; fuzzowane parsery |
| **Ryzyko rezydualne** | Kontakt widzi to, co mu wysyłasz (z definicji); może przestać odpowiadać (DoS w obrębie tego kontaktu) |

### 7. Złośliwy lokalny proces (ten sam UID)

| | |
|---|---|
| **Zdolności** | Proces tego samego użytkownika próbuje gadać z socketem IPC, czytać pliki, zrzucać RAM |
| **Obrona** | Socket `0o600` (tylko właściciel); token IPC wiązany z UID+PID (Linux `SO_PEERCRED`); token dopiero po `unlock`; sekrety zeroizowane przy `lock`; gating komend setup/RemoteDelete gdy sesja aktywna |
| **Ryzyko rezydualne** | Proces tego samego UID jest w dużej mierze **wewnątrz** granicy zaufania — czyta (zaszyfrowane) pliki, a przy wyścigu/zdobyciu tokenu steruje daemonem; zrzut RAM odblokowanego daemona ujawnia żywe klucze (świadome — „pamięć może zostać zdumpowana"). IPC to granica uprzywilejowana |

### 8. Łańcuch dostaw / zależności

| | |
|---|---|
| **Zdolności** | Złośliwa lub podatna zależność (C PQClean, opaque-ke, …), kompromitacja procesu budowania |
| **Obrona** | Pinowane wersje zależności; fuzzing powierzchni parsujących; OPAQUE/ML-KEM przez sprawdzone biblioteki (nie hand-rolled) |
| **Ryzyko rezydualne** | Kod C PQClean jest niezaudytowany (odnotowane w [kyberbox.md](kyberbox.md)) — dziedziczone side-channel/błędy pamięci; brak udokumentowanej gwarancji reproducible-build/SBOM; poza bezpośrednią kontrolą projektu |

### 9. Przeciwnik kwantowy (harvest-now-decrypt-later)

| | |
|---|---|
| **Zdolności** | Nagrywa szyfrogram dziś, deszyfruje później komputerem kwantowym |
| **Obrona** | Hybryda PQ wszędzie: ML-KEM-1024 + X25519 (KEM), ML-DSA-87 + Ed25519 (podpisy); złamanie wymaga pokonania połowy PQ; Argon2/AES-256/SHA-256 odporne na realistyczne przyspieszenie kwantowe |
| **Ryzyko rezydualne** | Jeśli **samo** ML-KEM padnie (kryptoanaliza, nie kwant), połowa X25519 ulega kwantowi → obie giną; to standardowe założenie hybrydy. Poprawność PQClean zakładana |

## Gwarancje forward secrecy i post-compromise security (warstwa E2E)

Precyzuje granice ochrony warstwy E2E (`lithiumd/src/e2e/`) wobec przeciwnika, który **w chwili T
przejmuje odblokowane urządzenie** i czyta `self_state` + `peer_state` (klasy 4-7 w wariancie pełnej
kompromitacji). Mechanikę kluczy opisują [crypto-protocol.md](../protocol/crypto-protocol.md) i [kyberbox.md](kyberbox.md);
tu chodzi o granice gwarancji.

**Co przeciwnik ma w chwili T:** klucze tożsamości kontaktu `ed_priv` + `dili_priv` (per kontakt,
**nie rotują** w obrębie parowania); RX keyring — klucze prywatne (X25519 + ML-KEM) wszystkich kluczy
odpowiedzi w oknie 32 od `ack_seq`; klucze bootstrapowe, jeśli KEM bootstrapu nie został jeszcze wycofany;
klucze mailbox i prekeye prywatne.

**Forward secrecy (wiadomości sprzed T) — oknowa, nie per-wiadomość.** Klucze RX starsze niż okno 32
od `ack_seq` są usuwane i zeroizowane (`gc_after_ack`, `RxKey: ZeroizeOnDrop`); wiadomości zaszyfrowane do
tych kluczy są w chwili T nieodszyfrowalne. Wiadomości wciąż w oknie (do ~32 ostatnich epok kluczy
odpowiedzi) **są** odszyfrowywalne ze skompromitowanego keyringu — to trailing window wystawiony przy
kompromitacji. Ziarno ML-KEM jest świeże per wiadomość, ale komponent X25519 jest wspólny w obrębie epoki,
więc jeden klucz RX odsłania całą epokę do niego zaszyfrowaną. Dopóki bootstrap nie został wycofany, klucze
bootstrapowe odsłaniają pierwsze wiadomości kontaktu.

**Post-compromise security (wiadomości po T) — warunkowa, tylko poufność, tylko wobec pasywnego.** Każda
wiadomość wstrzykuje nową entropię (świeże ziarno ML-KEM, świeży efemeryczny nadawcy, rotujące klucze RX).
Jeśli po T przeciwnik jest **pasywny**, to gdy obie strony przejdą na klucze RX wygenerowane po T (których
nie przechwycił), poufność nowych wiadomości **się odbudowuje** — klucze tożsamości nie służą do
deszyfrowania, więc ich posiadanie tu nie pomaga. Odbudowa jedzie na zwykłym ruchu; nie ma osobnej ceremonii
re-key. **Uwierzytelnienie nie odbudowuje się nigdy:** skoro `ed_priv`/`dili_priv` nie rotują, przeciwnik
**aktywny** bezterminowo podpisuje w imieniu ofiary i MITM-uje przyszłe reklamy kluczy — a przez MITM znów
łamie poufność przyszłych wiadomości. Wobec aktywnego przeciwnika PCS nie obowiązuje.

**Ryzyko rezydualne.** Trailing window (ostatnie ~32 epoki) to świadomy koszt tolerancji reorderingu —
patrz okno replay w [kyberbox.md](kyberbox.md). Brak rotacji tożsamości czyni pełną kompromitację urządzenia
**trwałą** w wymiarze uwierzytelnienia: jedyną odpowiedzią jest ponowne sparowanie kontaktu nowym kodem
zaproszenia (izolacja per kontakt — nowe parowanie to nowa tożsamość). Spójne z non-goalem „kompromitacja
endpointu z żywym, odblokowanym daemonem" ([security-model.md](security-model.md)) — ta sekcja mówi, *jak
daleko* sięgają skutki, nie obiecuje przed nimi ochrony.

## Poza zakresem (non-goals)

Świadomie nieobjęte — szczegóły w [security-model.md](security-model.md):

- **Gwarancja dostarczenia** — model dopuszcza zgubienie wiadomości; brak potwierdzeń i kolejek z gwarancją.
- **Recovery po utracie hasła lub kluczy** — utrata materiału klucza jest preferowana nad wektorami odzysku.
- **Ukrycie samego faktu korzystania z relaya** — przeciwnik widzący sieć wie, że klient łączy się z serwerem (brak wbudowanej anonimizacji warstwy połączenia).
- **Kompromitacja endpointu z żywym, odblokowanym daemonem** — przy aktywnej sesji klucze są w RAM.
- **Ochrona przed własnymi sparowanymi kontaktami** — to, co im wyślesz, zobaczą.
