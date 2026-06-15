# Hardening — kontekst sesji (handoff)

Plan źródłowy: `hardening.md` (inwentarz + propozycje napraw + kolejność wdrożenia w sekcji „Kolejność wdrożenia").

Decyzja bazowa: **zostajemy przy `pqcrypto`** (brak alternatywy). Goldeny ML-KEM/ML-DSA polegają na stabilności tej implementacji.

## Kolejność wdrożenia z hardening.md (mapa postępu)

1. **§7.1** nagłówek podpisywany ×3 → `lithiumd/src/e2e/header.rs` + `canonical_bytes()` — **ZROBIONE** (commit `hardening p1`/`p2`).
2. **§1+§2+§3 (binarne)** `labels.rs` per crate — **ZROBIONE** (commity p1/p2). Istnieją: `lithium_core/src/labels.rs`, `lithiumd/src/labels.rs`, `lithiums/src/labels.rs`.
3. **§5** golden vectory przy kodekach — **ZROBIONE** (częściowo niezacommitowane). Szczegóły niżej.
4. **§9 + §7.5 + §5-identity** cross-process `core::contract::*`:
   - §5-identity (format `server.identity` / magic `LITHIUPK`) — **ZROBIONE** (ta sesja, niezacommitowane).
   - §9 (nagłówki HTTP, ścieżki, pola body) + §7.5 (ctx `-req/-resp`) — **ZROBIONE** (ta sesja, niezacommitowane). Szczegóły w sekcji D.
5. §7.2 (`StoredMessage` ×2) + §10 (enumy trybów) — **ZROBIONE** (ta sesja, niezacommitowane). Szczegóły w sekcji E.
6. §8 (rejestr nazw pól JSON stanu jako stałe) — **RDZEŃ ZROBIONY** (pliki stanu E2E ratchet + odczyty kluczy tożsamości w invite/verify). Niezacommitowane. Szczegóły w sekcji F. Zostają pola warstwy IPC + StoredMessage-decode (świadomie odłożone, lista w F). §6/§7.3 (pełne otypowanie self/peer-state na structy) — wciąż nie zrobione.
7. §4 (Argon2 dup), §11, §12, §13 — porządkowe, nie zrobione.

## Co zrobione W TEJ SESJI (niezacommitowane)

### A. Dedup formatu `server.identity` (§5-identity / §2 LITHIUPK XPROC)
- NOWY `lithium_core/src/contract/identity_file.rs` — jedyny kodek `encode`/`decode` + golden layoutu (magic/wersja/framing `tag_len|tag|len_le|data`). Stałe: `MAGIC=b"LITHIUPK"`, `VERSION=0x01`, tagi `x25519/ed25519/mlkem1024/mldsa87`. Struktura `ServerIdentityKeys{ x25519, ed25519, mlkem1024, mldsa87 : Vec<u8> }`.
- NOWY `lithium_core/src/contract/mod.rs` (`pub mod identity_file;`).
- `lithium_core/src/lib.rs` — dodane `pub mod contract;`.
- `lithiums/src/identity.rs` — `write_server_identity` woła `encode`, tylko zapis pliku.
- `lithiumd/src/identity.rs` — `parse` woła `decode`, zostaje adaptacja na `ServerBootstrap` + daemon-specyficzna walidacja długości `Byte32` (błędy `server_identity_bad_x25519/ed25519`). Nazwy błędów `server_identity_*` zachowane (itest na nich polega).
- `lithium_itest/tests/daemon/common.rs::build_server_identity` — też przez `core::contract::identity_file::encode` (koniec 3. kopii formatu).

### B. Goldeny krypto: prawdziwy output, nie ręcznie wpisane wartości
Decyzja użytkownika: krypto-prymitywy mają pinować REALNY output (kierunek decrypt/verify ze zrzuconego wektora). WYJĄTEK: `keyfile`, `server.identity`, `mkfile` zostają syntetyczne (zrzut „prawdziwego" outputu = realny keyfile/identity/MK w teście — niepożądane).
- `lithium_core/tests/golden_tests.rs`:
  - `aead_blob_decrypts_to_pinned_plaintext` — było `encrypt` z ręcznym `nonce=0x22`; teraz KAT decrypt ze zrzuconego realnego blobu (key=`9f2c1b8a...`, blob=`01a14b7e02...`) + test, że zepsuty tag odrzuca. Usunięto nieużywany import `Byte12`.
  - `kyberbox_*` (decrypt z `testdata/kyberbox_golden_v1.txt`), `mldsa87_*` (verify z `testdata/mldsa87_verify_golden_v1.txt`) — bez zmian, już real-output.
- `lithiums/src/db/repo.rs` golden `sealed_msg_blob_opens_to_pinned_plaintext` — już decrypt realnego blobu, bez zmian.

### C. Pozostałe goldeny layoutu (syntetyczne, świadomie)
`keyfile.rs` (`keyfile_record_layout_is_pinned`), `invite_codec.rs` (`invite_code_layout_is_pinned`), `wire.rs` (`wire_packed_layout_is_pinned`), `password_provider.rs` (`mkfile_record_layout_is_pinned`) — framing z fikcyjnymi wejściami. Zostają.

## Stan weryfikacji
- `cargo build -p lithium_core -p lithiumd -p lithiums` OK.
- `cargo build --tests -p lithium_itest` OK.
- `cargo test -p lithium_core --lib` (6 ok, w tym `contract::identity_file::*`, `labels`, `keyfile`) + `--test golden_tests` (3 ok) OK.
- clippy czysty na `lithium_core --lib`, `lithiumd`, `lithiums`. ZNANY istniejący lint (NIE nasz): `approximate value of PI` w `lithium_core/tests/secret_tests.rs:412` (literał `3.14` w JSON), plik nietknięty.

### D. §9 + §7.5 cross-process protocol → `lithium_core::contract::protocol` (ta sesja, niezacommitowane)
NOWY `lithium_core/src/contract/protocol.rs` — jedyne źródło stałych protokołu klient<->serwer + piny:
- `mod header` (HTTP/JSON-headers): `KEY_X, KEY_K, SEED, DATA, SES_X, SES_K, SIG_ED, SIG_DILI, KEY_ED, KEY_DILI`.
- `mod field` (pola body): `HANDLER, PASSWORD, DEK, TOKEN, TOK, CAPABILITY, MAILBOX, CONTENT, DATA, TIMESTAMP, MSG`.
- `mod path` (ścieżki) + `mod ctx` (bazy ctx) — po jednym wpisie na endpoint.
- `fn ctx_req/ctx_resp(base)` (§7.5, `-req`/`-resp`), `fn format_timestamp(secs)` (`{:016x}`).
- testy: `registry_values_are_pinned`, `ctx_direction_suffixes_are_pinned`, `timestamp_is_zero_padded_16_hex`.

Podpięte (koniec 3 kopii kontraktu):
- klient `lithiumd/src/protocol_manager.rs` (`Endpoint::path/ctx_base` -> stałe, `ctx_req/ctx_resp` -> `protocol::*`, wszystkie literały nagłówków/pól + timestamp).
- klient `lithiumd/src/commands/contact_fetch.rs` (`field::MAILBOX`/`field::DATA`) i `contact_send.rs` (`field::MAILBOX`/`field::CONTENT`). UWAGA: `contact_fetch.rs::build_stored_message` `transport.mailbox` to koperta E2E, NIE protokół serwera — zostawione.
- serwer `lithiums/src/transport/mod.rs` (import jako `header as hdr` bo koliduje z `poem::http::header`), `api/user.rs`, `api/messages.rs`, `api/handshake.rs`, `lib.rs` (route paths + `CryptoCfg::*(ctx::*)`).
- itest `lithium_itest/src/client.rs` (Ep::path/ctx_base, json! body, nagłówki, RawShakeBuilder, `/shake`, `shake-req`).

Weryfikacja D: `cargo build -p lithium_core -p lithiumd -p lithiums` OK; `cargo build --tests -p lithium_itest` OK; `cargo test -p lithium_core --lib contract::` (7 ok); itesty `ds_messaging` (6 ok), `server` (32 ok), `replay_timestamp` (5 ok) — pełny round-trip klient<->serwer przez wspólne stałe działa.
Decyzja: `Endpoint` enum został w `lithiumd`, serwer dalej bez enuma; współdzielone są tylko stałe/funkcje z core (nie samo mapowanie). To wystarcza, bo to jedyne źródło stringów.

### E. §7.2 (StoredMessage) + §10 (enumy trybów) (ta sesja, niezacommitowane)
§7.2 — był podwójny koder utrwalanej wiadomości lokalnej: `contact_send.rs::build_stored_message` (derive-struct) i `contact_fetch.rs::build_stored_message` (ręczny `json!`), ten sam kształt, dekod w `messages_list.rs`.
- NOWY `lithiumd/src/commands/stored_message.rs` — jedyny koder `encode(text, ui, mailbox_hex, mailbox_gen) -> SecretBytes` + struct `StoredMessage`/`Transport` (derive Serialize) + golden `stored_message_layout_is_pinned`. Stałe: `STORED_MSG_V=1`, `KIND_TEXT="text/utf8"`.
- `commands/mod.rs` — `pub(crate) mod stored_message;`.
- `contact_send.rs` — usunięty lokalny `build_stored_message`, woła `stored_message::encode(plaintext.expose(), ...)`, kind w `encrypt_for_peer` przez `stored_message::KIND_TEXT`.
- `contact_fetch.rs` — usunięty lokalny `build_stored_message`, oba wywołania na `stored_message::encode`.
- `messages_list.rs` — dekod zostawiony (tolerancyjny, fallback `kind:"unknown"`); to jest §6/§8 (typowane decode) — na potem.

§10 — tryby E2E `"ratchet"/"bootstrap"/"prekey_recover"` były gołymi `&str`.
- `e2e/header.rs` — NOWY enum `E2eMode { Ratchet, Bootstrap, PrekeyRecover }` `#[serde(rename_all="snake_case")]` + `as_str()`. `SignedHeader.mode: String` -> `E2eMode`.
- `e2e/session.rs` — produkcja trybu w `encrypt_for_peer` na warianty enuma; `mode` (Copy, bez `to_owned`); meta `"mode": mode.as_str()`; odczyt `hdr.mode.as_str()` bez zmian semantyki.
- Golden `canonical_bytes_is_pinned` (header.rs) niezmieniony i przechodzi — enum serializuje się do identycznych bajtów (`"mode":"ratchet"`), więc podpisy bez rozjazdu.
- UWAGA: `"bootstrap"` jako KLUCZ stanu (`self_v["bootstrap"]`, `peer_v["bootstrap"]`) to inny byt (sub-obiekt stanu) — NIE ruszane, to §6/§8. `kind:"text"` w `header.rs` to tylko sample testowy; produkcyjny kind to zawsze `KIND_TEXT`.
- Message-kind `text/utf8` był w 3 miejscach (contact_send ×2: e2e-header arg + stored, contact_fetch stored) — teraz wszędzie `KIND_TEXT`.

Weryfikacja E: `cargo build -p lithiumd` OK; `cargo test -p lithiumd` 113 ok (w tym `stored_message_layout_is_pinned`, `canonical_bytes_is_pinned`); clippy lithiumd czysty; itest `ds_messaging` 6 ok (pełny round-trip send/fetch/list przez dwa daemony + serwer — koder i format trybu działają end-to-end).

### F. §8 rejestr nazw pól JSON stanu — RDZEŃ ZROBIONY (ta sesja, niezacommitowane)
Cel (życzenie usera): docelowo ZERO literalnych stringów-kluczy, wszystko jako stałe.

ZROBIONE w tym przebiegu:
- NOWY `lithiumd/src/state_fields.rs` — płaski rejestr `pub(crate) const`ów nazw pól dokumentów stanu self_v/peer_v (E2E ratchet). ~55 stałych: `E2E_RX, E2E_TX, E2E_PEER, BOOTSTRAP, NEED_RECOVER, PEER, MAILBOX, PREKEYS_LOCAL_PUBLIC, PREKEYS_ADVERTISED, PREKEYS_REMOTE, ACTIVE, ACK_SEQ, NEXT_SEQ, WINDOW, KEYS, SEQ, CID, ID, STEP, X_PUB, K_PUB, ED_PUB, DILI_PUB, X_PRIV, K_PRIV, ED_PRIV, DILI_PRIV, MBOX_IN_PUB/PRIV, MBOX_OUT_CUR_PUB/PRIV, MBOX_OUT_NEXT_PUB/PRIV, TX_GEN, TX_SENT, ROTATE_EVERY, PEER_TX_GEN_SEEN, SENDER_PUBS, RX_USED, TX_USED, RETIRE_OK, RETIRED_AT_MS, SEEN_AT_MS, CREATED_AT_MS, UPDATED_AT_MS, TS_MS, MSG_ID, MODE, KIND, MAILBOX_GEN`. Stała = `value.to_uppercase()` (np. `x_pub`->`X_PUB`). Test pinujący `registry_values_are_pinned`.
- `main.rs` — dodane `mod state_fields;`.
- Import aliasowany `use crate::state_fields as sf;` (alias `sf`, bo nazwa `field` koliduje z `contract::protocol::field` w plikach contact_*).
- GRUPA A (czyste pliki stanu — skonwertowane WSZYSTKIE literały w pozycji klucza: `["x"]`, `.get("x")`, `.get_mut("x")`, `get_string("x")`, klucz `json!` `"x":` -> `sf::X`): `e2e/state_self.rs`, `e2e/state_peer.rs`, `e2e/prekeys.rs`, `e2e/session.rs`, `e2e/crypto.rs`, `commands/contact_mailbox.rs`. Każdy ma `use crate::state_fields as sf;`.

GRUPA B (odczyty kluczy tożsamości) — ZROBIONE w tym przebiegu:
- `commands/invite_create.rs`, `commands/invite_accept.rs`, `commands/contact_verify_emoji.rs` — odczyty `cid/ed_pub/dili_pub` (`get_string`, `self_field`/`peer_field`) na `sf::*`; dodany `use crate::state_fields as sf;`.
- `commands/invite_codec.rs` — wszystkie testowe `get_string("...")` + tablica pól (`gen_self_state_has_all_required_fields`) na `sf::*`. UWAGA: import `sf` jest WEWNĄTRZ `mod tests` (sf używane tylko w testach tego pliku; import na poziomie pliku dawał unused_import). Non-test `SelfStateSerde` to derive serde (bez literałów).

WERYFIKACJA (przeszła): `cargo clippy -p lithiumd` czysto; `cargo test -p lithiumd` 114 ok (w tym `state_fields::tests::registry_values_are_pinned`); itesty `ds_messaging` 6 ok, `ds_invite_abuse` 5 ok. Zero literałów-kluczy w grupie A (sprawdzone grepem).

DODATKOWO ZROBIONE w tym przebiegu (domyka §7.2 po stronie decode):
- `commands/stored_message.rs` — dodany typowany `Decoded {kind,text,ui}` + `decode(bytes)->Option<Decoded>`.
- `commands/messages_list.rs` — ręczne `parsed.get("kind"/"text"/"ui")` zastąpione `stored_message::decode(...)`; usunięty zduplikowany fallback (Some/None idą w to samo `out.push`). Klucze ODPOWIEDZI IPC (`id,direction,kind,text,ui,created_at,messages,paging,has_more,next_before_id`) na razie literalne (przebieg IPC niżej). Wartość-sentinel `"unknown"` zostawiona (to wartość, nie klucz).

ODŁOŻONE (świadomie, osobny przebieg — inne dokumenty niż stan ratcheta):
- Pola warstwy IPC (lithiumg<->lithiumd): `contact_id, code, my_code, emojis, sent, direction, messages, paging, has_more, next_before_id, created_at, id, ok, err` + klucze `json!` w `messages_list.rs`, `invite_create.rs`, `invite_accept.rs`, `contact_verify_emoji.rs`, wyniki `contact_send/fetch`. Docelowo własny rejestr/typy (jak `contract::protocol` dla serwera). UWAGA cross-crate: sprawdzić czy `lithiumg` używa tych samych nazw (wtedy stałe do współdzielonego miejsca). To realizuje resztę życzenia usera „zero literałów".
- Testowe `json!`-buildy stanu w `contact_verify_emoji.rs` (`"cid":`,`"ed_pub":` itd., ~206-259) — można dokończyć `sf::*` (test-state buildy), drobne.
- Numeryczne klucze generacji w `sender_pubs` (`"0".."N"`) — dynamiczne wartości, NIE konwertować.
- §6/§7.3 (pełne otypowanie self_v/peer_v z `Value` na structy serde) — duży refaktor, po §8 (rejestr stałych daje fundament pod nazwy pól structów).

## Odłożone TODO (uwagi usera, na potem)
- **JSON error -> struct**: błędy/odpowiedzi serwera oparte na `serde_json::Value` + `get/get_string` powinny przejść na typowane structy (serde). Najpierw skończyć enum/format-hardening, potem to.
- **Lokalne stany -> structy**: lokalny stan kontaktu (`contact_mailbox.rs` `mailbox.*`, `self_v`/`peer_v` jako `Value`) i podobne lokalne JSON-y do typowanych structów. To pokrywa się z §6/§7.3/§8 (typowanie self/peer-state) — robić tam.

## NASTĘPNY KROK: §6 + §7.3 + §8 (typowanie self/peer-state + rejestr pól) — największy refaktor
Cel: `self_v`/`peer_v` (`serde_json::Value` mutowane po stringach) -> typowane structy; scentralizować rejestr nazw pól (§8). Tu wciągnąć odłożone TODO usera o lokalnych stanach i typowany decode w `messages_list.rs`.
- self_state pola: `e2e_rx{active,ack_seq,next_seq,window,keys}`, `bootstrap{rx_used,retire_ok,retired_at_ms,tx_used}`, `prekeys_local_public`, `prekeys_advertised`, `mailbox{tx_gen,tx_sent,rotate_every,...}`, `mbox_*` — `state_self.rs`, `contact_mailbox.rs`, `prekeys.rs`, `session.rs`.
- peer_state pola: `e2e_peer{id,x_pub,k_pub,step,updated_at_ms}`, `need_recover`, `bootstrap{tx_used}`, `prekeys_remote[...]`, `mailbox{sender_pubs,peer_tx_gen_seen}` — `state_peer.rs`, `session.rs`, `contact_mailbox.rs`.
- §8 rejestr nazw pól JSON tożsamości/kluczy (`cid,x_pub,k_pub,ed_pub,...`) — `invite_codec.rs`, `state_self.rs`, `crypto.rs`, `contact_verify_emoji.rs`.
Uwaga: to dotyka `SecretJson`/`with_exposed_mut` i jest najdelikatniejsze (ratchet). Robić małymi krokami z `cargo test -p lithiumd` + itest `ds_messaging` po każdym.
Potem zostaje: §4 (Argon2 dup), §11 (store namespaces serwera), §12, §13 — porządkowe.

## Uwagi stylu (przypomniane przez usera)
- Komentarze tylko „dlaczego", nigdy „co"; bez dekoracyjnych dividerów; bez znaków spoza klawiatury. (Patrz CLAUDE.md / pamięć `feedback_code_style`.)
- Goldeny krypto = realny output (decrypt/verify), bez ręcznie wpisanych nonce; format-pliki z materiałem klucza (keyfile/identity/mkfile) = syntetyczne.
