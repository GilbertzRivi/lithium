# Specyfikacja protokołu kryptograficznego Lithium

Dokument opisuje pełny protokół kryptograficzny Lithium w dwóch niezależnych warstwach: transport (daemon–serwer) i E2E (daemon–daemon). Przeznaczony dla audytorów i implementatorów.

## Dwie niezależne warstwy szyfrowania

Każda wiadomość przechodzi przez dwie niezależne warstwy szyfrowania:

1. **Warstwa E2E** — szyfrowanie między daemonami, niewidoczne dla serwera. Serwer nigdy nie ma kluczy do tej warstwy.
2. **Warstwa transportu** — szyfrowanie połączenia daemon–serwer. Chroni metadane żądania i payload E2E przed obserwatorem sieciowym. Serwer deszyfruje tę warstwę, ale zawartość jest już zaszyfrowana warstwą E2E.

Kompromitacja warstwy transportu nie ujawnia treści wiadomości — pozostają zaszyfrowane kluczami E2E per-kontakt.

## Prymitywy kryptograficzne

| Cel | Algorytm |
|-----|----------|
| KEM hybrydowy | X25519 + ML-KEM-1024 (via KyberBox) |
| AEAD | AES-256-GCM-SIV |
| KDF | HKDF-SHA256 |
| Podpisy | Ed25519 + ML-DSA-87 (dual-sign) |
| Hash haseł | Argon2id |
| CSRNG | `rand::rngs::SysRng` |

Szczegółowa analiza KyberBox: [kyberbox.md](kyberbox.md).

## Warstwa transportu (daemon–serwer)

### Tryb Shake

Używany do inicjalizacji sesji. Klient nie posiada jeszcze kluczy sesji serwera.

Klient wysyła w cleartext nagłówkach HTTP:
- `key-x` — efemeryczny klucz publiczny X25519 klienta (hex 32B)
- `key-k` — efemeryczny klucz publiczny ML-KEM-1024 klienta (hex 1568B)
- `seed` — zaszyfrowane ziarno KEM
- `data` — blob zaszyfrowanych nagłówków aplikacyjnych

Klient szyfruje ciało żądania przez KyberBox z kontekstem `"shake"`, używając długoterminowych kluczy publicznych serwera jako adresata (X25519 i ML-KEM-1024 z pliku `server.identity`) i własnego efemerycznego klucza prywatnego X25519 jako nadawcy. Serwer deszyfruje ciało swoim długoterminowym kluczem prywatnym X25519 oraz efemerycznym kluczem publicznym klienta z nagłówka `key-x`.

W zaszyfrowanych nagłówkach aplikacyjnych (`data`) klient umieszcza:
- `key-ed` — efemeryczny klucz publiczny Ed25519 (hex 32B)
- `key-dili` — efemeryczny klucz publiczny ML-DSA-87 (hex 2592B)
- `sig-ed` — podpis Ed25519 nad ciałem żądania
- `sig-dili` — podpis ML-DSA-87 nad ciałem żądania

Odszyfrowane ciało JSON musi zawierać pole `timestamp` (Unix timestamp w sekundach, hex 16 znaków, big-endian). Serwer waliduje `timestamp` w granicach ±60s od swojego zegara. Serwer weryfikuje podpis przy użyciu `key-ed` i `key-dili` z zaszyfrowanych nagłówków.

Odpowiedź serwera zawiera w cleartext nagłówkach HTTP:
- `key-x` — klucz publiczny X25519 nowej sesji (klient szyfruje do niego kolejne żądanie)
- `key-k` — klucz publiczny ML-KEM-1024 nowej sesji
- `data` — blob zaszyfrowanych nagłówków odpowiedzi (KyberBox)
- `seed` — zaszyfrowane ziarno KEM
- `sig-ed` — podpis Ed25519 serwera nad ciałem odpowiedzi
- `sig-dili` — podpis ML-DSA-87 serwera nad ciałem odpowiedzi

W zaszyfrowanych nagłówkach odpowiedzi (`data`) znajdują się:
- `ses-x` — losowy identyfikator klucza prywatnego X25519 sesji w `EphemeralStoreManager`
- `ses-k` — losowy identyfikator klucza prywatnego ML-KEM-1024 sesji w `EphemeralStoreManager`

Klient odsyła te identyfikatory w nagłówkach kolejnego żądania (`ses-x`, `ses-k`), a serwer używa ich do lookup klucza prywatnego. Klucze prywatne sesji są przechowywane w `EphemeralStoreManager` z TTL 60s (Shake) / 120s (Session).

### Tryb Session

Używany po wykonaniu Shake. Klient posiada klucze publiczne sesji z poprzedniej odpowiedzi.

Klient wysyła w cleartext nagłówkach HTTP:
- `ses-x` — losowy 32-bajtowy identyfikator sesji X25519 (hex) — otrzymany z zaszyfrowanych nagłówków poprzedniej odpowiedzi
- `ses-k` — losowy 32-bajtowy identyfikator sesji ML-KEM-1024 (hex) — otrzymany z zaszyfrowanych nagłówków poprzedniej odpowiedzi
- `seed` — zaszyfrowane ziarno KEM
- `data` — blob zaszyfrowanych nagłówków aplikacyjnych

W zaszyfrowanych nagłówkach aplikacyjnych (`data`) klient umieszcza `sig-ed`, `sig-dili`, oraz opcjonalnie `key-ed`/`key-dili` — zależnie od endpointu (patrz tabela niżej).

Klient szyfruje ciało przez KyberBox z kontekstem `"session"`, używając kluczy publicznych sesji serwera (otrzymanych z poprzedniej odpowiedzi w cleartext nagłówkach HTTP jako `key-x`, `key-k`) jako adresata. Serwer używa `ses-x`/`ses-k` jako kluczy lookup do `EphemeralStoreManager`, skąd pobiera odpowiednie klucze prywatne sesji, i deszyfruje ciało. TTL sesji: 120s.

Po każdej odpowiedzi serwer generuje nowe pary kluczy sesji i umieszcza je w nagłówkach — klient używa nowych kluczy do kolejnego żądania.

### Anti-replay

`GuardMiddleware` stosuje dwa mechanizmy:

1. **Hash ciała**: `SHA256(raw_body_bytes)` przechowywany w `EphemeralStoreManager` z TTL 600s. Pierwsze żądanie z danym hashem przechodzi. Ponowne użycie tego samego ciała w ciągu 600s zwraca `400 replay_detected`. Dotyczy tylko żądań POST — GET-y są zwolnione.

2. **Timestamp**: Pole `timestamp` w odszyfrowanym ciele musi być w granicach ±60s od zegara serwera. Poza tym oknem żądanie jest odrzucane.

### Podpisywanie i weryfikacja

Każde żądanie jest dual-podpisane (Ed25519 + ML-DSA-87). Klucze podpisujące i sygnatury są umieszczane w zaszyfrowanych nagłówkach aplikacyjnych — serwer weryfikuje je po deszyfrowaniu. Serwer zawsze weryfikuje oba podpisy — oba muszą przejść.

Zachowanie per endpoint:

| Endpoint | Klucze `key-ed`/`key-dili` w nagłówkach | `AuthMode` | Weryfikacja po stronie serwera |
|----------|------------------------------------------|------------|-------------------------------|
| `Shake`, `RemoteDelete`, `MsgFetch` | efemeryczne (generowane per żądanie) | `KeysInHeaders` | z zaszyfrowanych nagłówków żądania |
| `Register` | długoterminowe klucze tożsamości | `KeysInHeaders` | z zaszyfrowanych nagłówków żądania (serwer zapisuje je w DB) |
| `Login` | brak | `LoginByHandler` | kluczami zapisanymi w DB, wyszukanymi po `handler` |
| `Delete`, `MsgSend` | brak | `JwtUser` | tożsamość użytkownika z JWT wystawionego przy `Login` (nie z kluczy w nagłówkach) |

Serwer dual-podpisuje każdą odpowiedź swoimi kluczami. Klient weryfikuje pod kluczami załadowanymi z pliku `server.identity`.

### JWT (jednorazowy token autoryzacji)

JWT wystawiany przy pomyślnym logowaniu (`/user/login`), wymagany przez endpointy z `AuthMode::JwtUser`: wysłanie wiadomości (`/msg/send`) i usunięcie konta (`/user/delete`).

Nie istnieje żadna komenda IPC `login` i żaden ekran GUI logowania. `/user/login` jest wołane automatycznie i niewidocznie przez `ProtocolManager::ensure_login` (`lithiumd/src/protocol_manager.rs`) za każdym razem, gdy operacja wymagająca JWT (`contact_send`, `delete_account`) albo DEK-a (`unlock_storage`, `get_dek`) nie ma już zcache'owanego, niezużytego tokenu — używając handlera/hasła konta z `set_credentials`, trzymanych tylko w pamięci. Token jest jednorazowy (`store.take`), więc praktycznie każde kolejne wywołanie `contact_send`/`delete_account` po wyczerpaniu poprzedniego tokenu wywoła ponowny, równie niewidoczny `/user/login` w tle.

- Algorytm: HS256
- Pole `sub`: `hex(HMAC-SHA256(user_id_bytes, random_seed_bytes))` — nieprzejrzysty identyfikator
- Token przechowywany w `EphemeralStoreManager` pod wartością HMAC `sub` z TTL sesji
- Token jest **jednorazowy** — `store.take` usuwa go przy pierwszym użyciu
- W ciele JSON jako `tok_hex` (hex-encoded)

Utrata tokenu lub przejęcie sesji nie pozwala na wielokrotne użycie — token jest zużyty.

### Endpointy transportowe

| Endpoint | Ścieżka | Tryb krypto | `key-ed`/`key-dili` w zaszyfrowanych nagłówkach |
|----------|---------|-------------|--------------------------------------------------|
| Shake | POST `/shake` | Shake | efemeryczne |
| Rejestracja | POST `/user/register` | Session | tożsamości (zapisywane w DB) |
| Logowanie | POST `/user/login` | Session | brak (serwer weryfikuje po `handler` z DB) |
| Delete | POST `/user/delete` | Session | brak (serwer weryfikuje przez JWT) |
| Wysłanie | POST `/msg/send` | Session | brak (serwer weryfikuje przez JWT) |
| Remote delete | POST `/user/revoke` | Session | efemeryczne |
| Pobranie | POST `/msg/fetch` | Session | efemeryczne |
| Root | GET `/` | brak | brak |
| Health | GET `/health` | brak | brak |

### Padding rozmiarów

Ciało i nagłówki są paddowane losowo przed szyfrowaniem:
- Body: `data || 0x80 || 0x00...` do wielokrotności losowego bloku 32–64 KB
- Nagłówki: paddowane do wielokrotności losowego bloku 4–8 KB

Ukrywa długość i typ operacji przed obserwatorem sieciowym.

## Warstwa E2E (daemon–daemon)

### Format WireV1 — binarny format wiadomości

```
[LM1: 3 bajty magic]
[VER: 1 bajt = 1]
[to_id: 32 bajty]        identyfikator klucza odbiorczego
[from_x_pub: 32 bajty]   efemeryczny X25519 nadawcy
[seed_len: 2 bajty BE]
[seed: seed_len bajtow]  ML-KEM ciphertext + zaszyfrowany seed
[hdr_len: 4 bajty BE]
[enc_headers: hdr_len bajtow]
[body_len: 4 bajty BE]
[enc_body: body_len bajtow]
```

`to_id = HKDF(x_pub_bytes || k_pub_bytes, info="lithiumd/e2e-peer-kid/v1")` — identyfikator pary kluczy odbiorczych adresata.

`enc_headers` i `enc_body` to blobs KyberBox z kontekstem `"lithiumd/e2e-msg/v1"`.

### Szyfrowanie E2E (KyberBox w kontekście E2E)

Szyfrowanie używa kluczy per-kontakt, nie kluczy transportowych. Klient szyfruje do kluczy publicznych peera (`peer_pub_x`, `peer_k_pub`), używając świeżo wygenerowanego klucza efemerycznego X25519 (`from_x_pub`).

`headers` zawierają metadane (tryb wiadomości, reply keys, mailbox info, podpisy). `body` zawiera treść wiadomości.

### Tryby szyfrowania E2E

**Bootstrap** — pierwsza wiadomość do kontaktu:
- Celuje w klucze bootstrapowe z zaproszenia (`x_pub`, `k_pub` z kodu `lci1:`)
- Nadawca nie ma kluczy odpowiedzi od peera
- Klucze bootstrapowe są usuwane z `self_state` gdy peer potwierdzi odbiór (`ack_seq > 0` lub `retire_ok`) i ma ustawiony `e2e_peer`

**Ratchet** — po odebraniu pierwszej wiadomości zwrotnej:
- Celuje w klucze `reply` z ostatnio odebranej wiadomości (`e2e_peer.id`, `e2e_peer.x_pub`, `e2e_peer.k_pub`)
- Klucze RX są rotowane przy każdej odebranej wiadomości
- Klucze RX starsze niż okno 32 sekwencji od `ack_seq` są usuwane

**Prekey recover** — odzysk po desynchronizacji stanu:
- Celuje w prekey opublikowany przez peera (`prekeys_remote`)
- Pozwala wznowić komunikację bez nowej wymiany zaproszeń
- Prekey jest usuwany po użyciu

### Podpisywanie wiadomości E2E

Każda wiadomość jest dual-podpisana kluczami tożsamości kontaktu (Ed25519 + ML-DSA-87):

```
sig_input = "lithiumd/e2e-msg-sig/v1" || to_id || from_x_pub
            || u32(len(hdr_unsigned)) || hdr_unsigned
            || u32(len(body)) || body
```

`hdr_unsigned` to nagłówek JSON **bez** pól `auth`. Sygnatury są wbudowane w `enc_headers` — serwer ich nie widzi.

Odbiorca weryfikuje oba podpisy pod kluczami peera zapisanymi przy wymianie zaproszeń. Nieweryfikowalna sygnatura = odrzucenie wiadomości.

### Klucze odbiorcze (RX keyring)

Przy każdym wysłaniu nadawca generuje nową parę RX (X25519 + ML-KEM-1024) i wysyła klucze publiczne w zaszyfrowanym nagłówku (`reply`). Peer szyfruje kolejną wiadomość do tych kluczy.

Klucze RX przechowywane w `self_state["e2e_rx"]["keys"]` z numerem sekwencji (`seq`). Okno: 32 klucze od `ack_seq`. Starsze są bezpiecznie kasowane.

### Prekeys

Przy pierwszym wysłaniu generowany jest zestaw prekeys (domyślnie 5). Publiczne części dołączane do nagłówka wiadomości. Peer zapisuje je w `peer_state["prekeys_remote"]`.

Prywatne części przechowywane w tabeli `prekeys` SQLite (zaszyfrowane DEK-iem, AAD=`lithiumd/prekey/v1`). Prekey usuwany po użyciu (`take_prekey`).

## System mailbox

### Adresowanie

Adres mailbox to kryptograficznie pseudolosowy 32-bajtowy identyfikator skrzynki na serwerze. Serwer widzi wyłącznie adres — nie wie kto do kogo pisze.

```
shared  = ECDH(sender_out_priv, receiver_in_pub)
salt    = sender_cid || receiver_cid || generation (8 bajtow BE)
address = HKDF(shared, salt=salt, info="lithium/mbox/address/v1")  -> 32 bajty
```

Nadawca i odbiorca obliczają adres niezależnie — bez komunikacji z serwerem.

### Klucze mailbox per kontakt

Klucze mailbox są **dedykowanymi** parami X25519 generowanymi wyłącznie na potrzeby adresowania skrzynek. Są niezależne od kluczy używanych do szyfrowania treści wiadomości (klucze bootstrapowe, ratchet RX, prekey) — te dwie przestrzenie kluczy są całkowicie rozdzielone.

Każdy kontakt ma w `self_state`:
- `mbox_in_priv` / `mbox_in_pub` — stabilny klucz odbiorczy (niezmienny)
- `mbox_out_cur_priv` / `mbox_out_cur_pub` — bieżący klucz nadawczy
- `mbox_out_next_priv` / `mbox_out_next_pub` — następny klucz nadawczy (przygotowany z wyprzedzeniem)

### Rotacja klucza nadawczego

Po `rotate_every` (domyślnie 32) wysłanych wiadomościach: `cur <- next`, generuje nowe `next`. Zaszyfrowane nagłówki E2E (`enc_headers`) przekazują peerowi klucze publiczne `sender_cur_x_pub` i `sender_next_x_pub` — serwer ich nie widzi.

### Zakres fetch

`ContactFetch` sprawdza generacje `peer_tx_gen_seen - 2` do `peer_tx_gen_seen + 1` — do 4 generacji. Zapewnia odbiór wiadomości mimo przeskoczenia generacji po stronie nadawcy.

## Wymiana zaproszeń (parowanie kontaktów)

### Format kodu zaproszenia `lci1:`

```
lci1:<HEX>
```

Zawartość binarna (hex-encoded):

```
[LCI1: 4 bajty magic]
[VER: 1 bajt = 1]
[contact_id: 32 bajty]
[x_pub: 32 bajty]              X25519 (E2E)
[k_pub_len: 2 bajty BE = 1568]
[k_pub: 1568 bajtow]           ML-KEM-1024 (E2E)
[ed_pub: 32 bajty]             Ed25519 (podpisy)
[dili_pub_len: 2 bajty BE = 2592]
[dili_pub: 2592 bajtow]        ML-DSA-87 (podpisy)
[mbox_in_pub: 32 bajty]        stabilny klucz odbiorczy mailbox
[mbox_out_cur_pub: 32 bajty]   biezacy klucz nadawczy mailbox
[mbox_out_next_pub: 32 bajty]  nastepny klucz nadawczy mailbox
```

Laczny rozmiar danych binarnych: **4361 bajtow** — **8722 znaki hex** po `lci1:`.

### Przebieg wymiany

```
Strona A: create_invite -> kod lci1:HEX (klucze publiczne A)
Strona A przesyla kod B kanałem OOB (email, telefon, inne)
Strona B: accept_invite(kod A, contact_id=null) -> my_code (klucze publiczne B)
Strona B przesyla my_code do A kanałem OOB
Strona A: accept_invite(my_code, contact_id=A_contact_id)
Obie strony: peer_set=true -> moga pisac
```

Serwer nie uczestniczy w wymianie zaproszeń — kody są wymieniane poza serwerem.

### Weryfikacja tożsamości out-of-band

Po wymianie obie strony weryfikują 12-znakowy fingerprint (SAS — Short Authentication String, alfabet 64 znaków: litery, cyfry, symbole, greckie litery) kanałem głosowym lub osobistym.

Każda strona najpierw liczy własny "party transcript" — HKDF po konkatenacji 8 pól tożsamości (własny `cid`, `x_pub`, `ed_pub`, `dili_pub`, `k_pub` oraz 3 klucze mailbox: `mbox_in_pub`, `mbox_out_cur_pub`, `mbox_out_next_pub`) pod etykietą `PARTY_TRANSCRIPT_LABEL` (`"lithiumd/party-transcript/v1"`):

```
bundle  = cid || x_pub || ed_pub || dili_pub || k_pub || mbox_in_pub || mbox_out_cur_pub || mbox_out_next_pub
t_self  = HKDF(bundle, info="lithiumd/party-transcript/v1")          -> 32 bajty
t_peer  = HKDF(bundle_peer, info="lithiumd/party-transcript/v1")     -> 32 bajty (te same pola, dla peera)
```

Następnie oba transkrypty są sortowane (`t_a, t_b = sorted(t_self, t_peer)`), tak by obie strony liczyły identyczny `info`, i fingerprint liczony jest z ECDH:

```
shared    = ECDH(self_x_priv, peer_x_pub)
12 bajtow = HKDF(shared, info="lithiumd/contact-verify-emoji/v1" || t_a || t_b)
emoji[i]  = EMOJI_TABLE[bajt[i] mod 64]
```

Włączenie `t_a`/`t_b` do `info` wiąże fingerprint nie tylko z kluczem X25519, ale z całym zestawem tożsamości i kluczy mailbox obu stron — podmiana jakiegokolwiek z 8 pól po jednej ze stron zmienia wynikowy SAS. Identyczne emoji po obu stronach potwierdza brak MITM przy wymianie.

Długość 12 symboli (alfabet 64 → 72 bity) jest parametrem bezpieczeństwa: wymiana zaproszeń nie ma commitmentu kluczy, więc MITM kontrolujący kanał OOB może grindować własny zestaw kluczy offline, aby dopasować SAS ofiary. Grind jest HKDF-zależny (tani na GPU), dlatego jedyną samodzielną obroną (bez commit-reveal) jest dostatecznie długi ciąg — 2^72 ewaluacji jest niewykonalne nawet klastrowo.

## Cykl życia kluczy

### Master Key (MK)

MK jest nadrzędnym kluczem szyfrującym wszystkie pliki kluczy na dysku. Przechowywany zaszyfrowany przez `MkProvider`, którego implementacja zależy od komponentu:

- `lithiumd` — `PlainFileMkProvider`: MK zaszyfrowany hasłem danych (Argon2id + AES-256-GCM-SIV), plik `.keyf`.
- `lithiums` — domyślnie (feature `tpm`, włączona z definicji) `TpmMkProvider`: MK zapieczętowany w TPM jako obiekt KEYEDHASH, pod parent key ECC P-256 derywowanym deterministycznie z owner seed TPM (parent nigdy nie jest persystowany). Zapieczętowany blob trzymany w `LITHIUM_TPM_SEALED_PATH`. Fallback na `PlainFileMkProvider` (plaintext-na-dysku, analogicznie do `lithiumd`) tylko gdy `LITHIUM_MK_PROVIDER=plain` lub feature `tpm` wyłączona przy kompilacji.

`lithiums` nigdy nie trzyma MK w czystym plaintext na dysku w konfiguracji domyślnej.

Rotacja co 3600s (1 godzina), wykrywana i wywoływana przez `MkRotator` budzący się co 30s.

Rotacja jest crash-safe:
1. Zapisz stary i nowy MK w `.rotate/`
2. Przygotuj wszystkie pliki `.keyf` z nowym opakowaniem w `.rotate/staged/`
3. Zapisz marker `.rotate/ready`
4. Zastosuj staged pliki do lokalizacji docelowych
5. Zaktualizuj MK u providera
6. Usuń katalog `.rotate/`

Przy starcie `KeyManager` wykrywa niedokończoną rotację i kontynuuje lub wycofuje.

### DEK (Data Encryption Key)

DEK szyfrowania lokalnej bazy SQLite jest wyprowadzany z `combined_root`:

```
root_salt       = losowa 32-bajtowa sol, trwale zapisana w pliku root.salt (ensure_root_salt)
password_root   = Argon2id(data_password, salt=root_salt)
combined_root   = HKDF(input=server_dek, salt=password_root, info="lithium/user-provider/combined/v1")
db_dek          = HKDF(combined_root, info="lithium/db-dek/v1")
```

Sól nie jest stałą etykietą — jest losowa per instalacja i przechowywana w `root.salt` obok plików `.keyf` (`lithiumd/src/password_provider.rs`).

`server_dek` to blob DEK zaszyfrowany hasłem konta, przechowywany na serwerze jako nieprzejrzysty blob. Serwer go nie używa — zwraca przy logowaniu.

Bez `server_dek` (wymagającego aktywnej sesji z serwerem) lub bez `data_password` nie można wyprowadzić `db_dek`. Jest to świadoma właściwość modelu.

### Klucze per kontakt

Każdy kontakt ma niezależny zestaw kluczy generowany losowo z CSRNG przy tworzeniu zaproszenia:
- X25519 + ML-KEM-1024 (szyfrowanie E2E)
- Ed25519 + ML-DSA-87 (podpisy E2E)
- 3 pary kluczy mailbox (in, out_cur, out_next)

Kompromitacja kluczy jednego kontaktu nie kompromituje pozostałych.

### Klucze RX i bootstrap

Klucze bootstrapowe (z kodu zaproszenia) są przechowywane jako tajny materiał i usuwane z `self_state` gdy tylko peer potwierdzi odbiór i ratchet jest ustanowiony.

Klucze RX (reply) są rotowane przez ratchet — przy każdej odebranej wiadomości peer załącza nową parę RX, nadawca używa jej przy kolejnym wysłaniu. Stare klucze RX (poza oknem 32) są bezpiecznie kasowane.

### Klucze sesji transportowej

Klucze sesji (X25519 + ML-KEM-1024) generowane są przez serwer przy każdej odpowiedzi i przechowywane w `EphemeralStoreManager`. TTL: 60s (Shake) lub 120s (Session). Restart serwera niszczy wszystkie klucze sesji.

### Klucze wiadomości na serwerze

Każda wiadomość na serwerze jest szyfrowana **losowym kluczem per wiadomość** (nie DEK serwera). Klucz jest przechowywany wyłącznie w `EphemeralStoreManager` z TTL 24h. Restart serwera niszczy klucze — przechowywane wiadomości stają się trwale nieodszyfrowalne dla serwera.

Treść wiadomości jest dodatkowo zaszyfrowana przez klienta warstwą E2E przed dotarciem do serwera, więc serwer i tak nie może jej odczytać.

## Szyfrowanie bazy danych (serwer)

### Schemat szyfrowania pól użytkownika

Każde pole w tabeli `users` szyfrowane jest indywidualnie pod DEK serwera z osobnym AAD:

| Pole | AAD |
|------|-----|
| `password_hash` | `"user-password-hash/v1"` |
| `handler` | `"user-handler/v1"` |
| `ed_key` | `"user-ed-key/v1"` |
| `dili_key` | `"user-dili-key/v1"` |
| `dek` | `"user-dek/v1"` |

Podmiana DEK lub użycie nieprawidłowego AAD skutkuje błędem deszyfrowania AEAD.

### Deterministyczne ID użytkownika

```
handler (znormalizowany) -> UUID v5(namespace, handler) -> id_bytes
id_enc = AES-256-GCM-SIV(id_bytes, db_dek, nonce=HKDF(id_bytes, db_dek, UIDENC_NONCE_LABEL), aad="user-idenc/v1")
```

Ten sam handler zawsze daje ten sam `id_enc` — umożliwia wyszukiwanie PK bez przechowywania plaintext handlera. Świadomy trade-off opisany w [security-model.md](security-model.md).

## Format pliku klucza (.keyf)

Klucze prywatne i sekrety są przechowywane w plikach `.keyf` z podwójnym opakowaniem:

```
[KEYF magic: 4 bajty][version: u8][alg_id: u8][dek_len: u16]
[salt_len: u16][salt: 32 bajty]
[nonce_wrap_len: u16][nonce_wrap: 12 bajtow]
[ct_wrap_len: u16][ct_wrap: N bajtow]        AES-256-GCM-SIV(DEK, KEK)
[nonce_payload_len: u16][nonce_payload: 12 bajtow]
[ct_payload_len: u32][ct_payload: M bajtow]  AES-256-GCM-SIV(secret, DEK)
```

- **KEK** = `HKDF(MasterKey, salt, info="kek/v1")`
- **DEK** = losowy 32-bajtowy klucz per plik
- AAD zawiera wersję i typ klucza — błędny typ = błąd deszyfrowania

Zapis atomowy: `tmp + rename` z `fsync` i uprawnieniami `0o600` (Unix).

Rewrapping (zmiana MK bez deszyfrowania payload):
```
rewrap_keyfile_dek(path, old_mk, new_mk, key_type)
```
Deszyfruje i re-szyfruje wyłącznie warstwę DEK — payload kryptograficzny pozostaje nienaruszony.

## Format pliku server.identity

Plik binarny generowany przez serwer przy pierwszym uruchomieniu. Format (`lithium_core/src/contract/identity_file.rs`): magic 8-bajtowy, wersja, licznik wpisów, dalej sekwencja TLV (tag+dlugosc+dane) per klucz — nie sztywny layout:

```
[magic: 8 bajtow = "LITHIUPK"]
[version: u8 = 1]
[count: u8 = 4]
4x [tag_len: u8][tag: ASCII][data_len: u16 LE][data]
    tagi: "x25519" (32B), "ed25519" (32B), "mlkem1024" (1568B), "mldsa87" (2592B)
```

Nieznane tagi sa ignorowane przy deserializacji (forward-compat). Cztery znane klucze musza wystapic i miec dokladnie oczekiwana dlugosc (32/32/1568/2592) — `decode` odrzuca plik z brakujacym lub zle dlugim kluczem, zanim zaakceptuje go `set_server_identity`. Rzeczywisty rozmiar pliku z 4 wpisami: **4275 bajtow** (10 bajtow naglowka + 41 bajtow narzutu TLV + 32 + 32 + 1568 + 2592 bajtow danych).

Klient ładuje ten plik przy starcie i weryfikuje pod nim każdą odpowiedź serwera. Zmiana kluczy serwera bez aktualizacji pliku po stronie klienta zrywa komunikację trwale na poziomie kryptograficznym (deszyfrowanie zadania przez serwer lub weryfikacja podpisu odpowiedzi przez klienta zawodzi) — jest to celowe, patrz [security-model.md](security-model.md).