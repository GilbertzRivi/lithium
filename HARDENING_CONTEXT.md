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
7. §4 (Argon2 dup) — **ZROBIONE** (ta sesja, niezacommitowane). Szczegóły w sekcji G.
8. §11 (przestrzenie nazw store serwera) — **ZROBIONE** (ta sesja, niezacommitowane). Szczegóły w sekcji G.
9. §7.3 read-half (dedup pakietu tożsamości) + domknięcie literałów §8 — **ZROBIONE** (ta sesja, niezacommitowane). Szczegóły w sekcji H.
10. §6 (self_v/peer_v Value -> structy serde) — **NIEZROBIONE**, największy refaktor (patrz NASTĘPNY KROK).
11. §12, §13 — już stałe (`ST_*` w protocol_manager, layout keystore w manager.rs); zostaje tylko opcjonalne zebranie + `key_type`->enum (§13), niski priorytet, nie zrobione.

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
Potem zostaje już tylko §13 (opcjonalny `key_type`->enum, niski priorytet).

### G. §4 (Argon2 dup) + §11 (store namespaces serwera) (ta sesja, niezacommitowane)
§4 — parametry Argon2id (`m=64*1024, t=3, p=1, out=32`) były zduplikowane w 3 miejscach (`passwords.rs::argon2_std`, `passwords.rs::derive_wrap_key`, `password_provider.rs::argon2_32`); muszą być identyczne, by odszyfrować.
- `lithium_core/src/labels.rs` — nowe stałe `ARGON2_M_COST/T_COST/P_COST/OUT_LEN` + pin w `registry_values_are_pinned`.
- `lithium_core/src/crypto/kdf.rs` — nowa `pub fn argon2id() -> Result<Argon2<'static>>` (jedyny konstruktor, czyta stałe).
- `passwords.rs` — usunięty `argon2_std`, `hash_password_phc`/`verify_password_phc`/`derive_wrap_key` wołają `kdf::argon2id()`; usunięte importy `Algorithm/Argon2/Params/Version`.
- `lithiumd/password_provider.rs::argon2_32` — woła `kdf::argon2id()`; usunięty `use argon2::*` i martwa zależność `argon2` z `lithiumd/Cargo.toml`.
- Weryfikacja: core lib 9 ok, crypto_tests 93 ok, store_tests 14 ok (PHC + DEK wrap roundtrip), lithiumd 114 ok, itest `daemon_basic` 7 ok (realny unlock/lock/wipe przez `argon2_32`), clippy czysto.

§11 — prefiksy store (`auth:`/`guard:`/`replay:`/`token:`) rozsiane po `format!` w guard.rs i transport/mod.rs.
- NOWY `lithiums/src/store_keys.rs` — buildery `login_fail/login_lock/register_fail/register_lock/pre_replay_fail/pre_replay_lock/replay/token` (przyjmują już-znormalizowany id) + pin `store_key_namespaces_are_pinned`. `lib.rs`: `pub(crate) mod store_keys;`.
- `guard.rs` (`pre_replay_*_key`, `anti_replay_check`) i `transport/mod.rs` (`login/register_*_key`, oba `token:`) wołają buildery. Normalizacja (`normalize_login_handler`/`normalize_guard_remote`) zostaje przy call-site (domenowa).
- Weryfikacja: lithiums lib 3 ok (w tym pin), itest `server` 32 ok (login rate-limit/replay/token end-to-end), clippy czysto (jedyny warning to istniejący `picky-asn1`, nie nasz).

### H. §7.3 (read-half pakietu tożsamości) + domknięcie §8 literałów (ta sesja, niezacommitowane)
§7.3 — blok „czytaj publiczne pola tożsamości z self_state do `InvitePublic`" był zduplikowany 3× (invite_create ×2, invite_accept ×1), ~45 linii `match get_string` każdy, w dodatku z surowymi literałami `"x_pub"/"k_pub"/"mbox_*"` (niedokończone §8).
- `commands/invite_codec.rs` — NOWA `pub fn invite_public_from_self(&SecretJson) -> Result<InvitePublic>` (8 pól przez `sf::*`). Import `sf` przeniesiony na poziom pliku (był w `mod tests`).
- `invite_create.rs` / `invite_accept.rs` — oba/jeden blok zwinięte do `invite_public_from_self(&self_json)`; usunięte importy `InvitePublic`/`sf`. invite_accept: literał `"peer"` -> `sf::PEER` (zostaje `use sf`).
§8 domknięcie pozostałych literałów-kluczy dokumentów stanu (poza GRUPA A):
- `contact_verify_emoji.rs` — wszystkie odczyty SAS (`self_field`/`peer_field`): `"x_priv"/"x_pub"/"k_pub"/"mbox_*"/"peer"` -> `sf::*` (prod + test-buildy `bundle`/`self_view`/`peer_view` + lista pól w `swapping_*`). Kolejność argumentów `party_transcript` NIETKNIĘTA = bajty SAS bez zmian.
- NOWA stała `sf::LABEL = "label"` (+ pin).
- `contact_list.rs` — `v.get("label")` -> `sf::LABEL`, `v.get("peer")` -> `sf::PEER` (klucze IPC `json!` zostają).
- `contact_send.rs` — `self_state["prekeys_local_public"]` -> `sf::PREKEYS_LOCAL_PUBLIC`.
- `contact_fetch.rs` — 4 odczyty `ui.get("mailbox_gen")/("msg_id")` -> `sf::MAILBOX_GEN/MSG_ID` (klucze wyjściowe IPC `json!` i `"recovered"` zostają — warstwa IPC, odłożona).
- Weryfikacja: lithiumd 114 ok (w tym oba testy SAS), clippy `--tests` czysto, itest `ds_invite_abuse` 5 ok, `ds_messaging` 6 ok (pełny invite handshake + send/fetch/list).

UWAGA: to był read-half §7.3 + zamknięcie literałów §8. Pełne §6 (self_v/peer_v -> structy) ROZPOCZĘTE w sekcji I.

### I. §6 START — typowanie pod-dokumentów stanu na serde-structy (ta sesja, niezacommitowane)
Podejście: NOWY `lithiumd/src/e2e/state.rs` (`pub(crate) mod state;` w `e2e/mod.rs`) z serde-structami pod-dokumentów; parse-out (`from_value`) -> operuj -> write-back (`to_value`). Publiczne sygnatury funkcji BEZ ZMIAN (callerzy nietknięci). Każdy struct, którego pola pokrywają komplet kluczy danego pod-obiektu, pozwala USUNĄĆ odpowiednie `sf::*` (nazwę trzyma teraz serde) — zrobione dla `SEEN_AT_MS`, `UPDATED_AT_MS`.

Structy zrobione (3), wszystkie zweryfikowane (lithiumd 114 + clippy + `ds_messaging` 6 po każdym istotnym):
1. `RemotePrekey {id,x_pub,k_pub,seen_at_ms(#[serde(default)])}` — `state_peer.rs::merge_remote_prekeys_into_peer` (Vec<RemotePrekey> zamiast ręcznego `json!` push) + `peer_pick_remote_prekey` (from_value). Usunięto `sf::SEEN_AT_MS`.
2. `LocalPrekeyPublic {id,x_pub,k_pub,created_at_ms}` — `prekeys.rs::gen_local_prekey_material` `public_item` przez `to_value` zamiast `json!`. (`LocalPrekeyPriv` był już structem, został lokalny.)
3. `E2ePeer {id,x_pub,k_pub,step,updated_at_ms(#[serde(default)])}` — zapis w `session.rs` (reply -> e2e_peer) przez `to_value`; odczyt w `state_peer.rs::ensure_peer_e2e` przez `from_value` (let-chain `&&`, edition 2024). Usunięto `sf::UPDATED_AT_MS`. UWAGA: odczyt `peer_v[E2E_PEER][STEP]` w `session.rs:79` (peer_step_cur) zostawiony jako Value-read (działa na null gdy brak e2e_peer).
4. `RxKey {x_priv,x_pub,k_priv,k_pub,seq,created_at_ms}` — wpis mapy reply-keys. Insert w `session.rs::encrypt_for_peer` przez `to_value`; gettery `state_self.rs::self_get_rx_privs` (prywatne klucze) i `self_find_seq` przez `from_value`. Usunięto `sf::CREATED_AT_MS`. UWAGA: `gc_after_ack` i `ensure_self_keyring` wciąż iterują mapę i czytają `.seq` jako Value (sf::SEQ zostaje) — typowanie kontenera `E2eRx` to dalszy krok.
5. `MsgMeta {ts_ms,msg_id,kind:Option<String>(skip_if_none),step,mode:E2eMode,mailbox_gen}` — meta/ui zwracane z `encrypt_for_peer` (kind=None) i `decrypt_with_privs` (kind=Some). Oba `json!` -> `to_value`. Kolejność pól = poprzednia, serializacja bajt-identyczna (encrypt pomija kind). Usunięto `sf::TS_MS/MODE/KIND` ORAZ `E2eMode::as_str` (serde przejął string trybu, §10 domknięte typem). Testy session: asercje trybu przez `meta_mode()` helper (`from_value::<MsgMeta>().mode == E2eMode::*`) zamiast `meta.get(sf::MODE).as_str()`. UWAGA: `kind` w MsgMeta to inny byt niż `kind` w `StoredMessage`/`KIND_TEXT` (tamto stała wartości, nie pole meta).

6. `BootstrapState {rx_used:bool, tx_used:Option<bool>(skip_if_none), retire_ok:bool, retired_at_ms:u64}` — self `{rx_used,retire_ok,retired_at_ms}` + peer `{tx_used}` w jednym. `tx_used` Option bo init = `had_e2e` tylko gdy absent (presence-check). Helper `load_bootstrap`. Konwersja w `state_self.rs` (drop/mark/ensure) i `state_peer.rs` (ensure_peer_e2e). Test mark przez `load_bootstrap(v).retire_ok`. Usunięto `sf::RX_USED/TX_USED/RETIRE_OK/RETIRED_AT_MS`.
7. `E2eRx {active,ack_seq,next_seq,window, keys:BTreeMap<String,RxKey>}` (`#[serde(default)]` + custom Default: next_seq=1, window=DEFAULT_WINDOW) — RDZEŃ RATCHETA ODBIORCZEGO. **KLUCZOWE BEZP.**: `RxKey` dostał `#[derive(Zeroize, ZeroizeOnDrop)]`, a `store_e2e_rx` zeroizuje stary Value (`SecretJson::from(mem::replace(...))`) — zachowuje zeroizację reply-keys z dawnego `drop_removed_json_key` (gc `retain` dropuje RxKey -> zeroize). Helpery `load_e2e_rx`/`store_e2e_rx`/`set_active_reply_key`/`advance_ack` w `state_self.rs` (pub(crate)). Konwersja: `ensure_self_keyring` (init+stale-bootstrap-slot removal), `self_next_seq/find_seq/get_rx_privs`, `gc_after_ack`, `drop_bootstrap` (ack_seq read); `session.rs` encrypt (`set_active_reply_key`) i decrypt (`advance_ack`). Testy state_self/session czytają e2e_rx przez `load_e2e_rx`/`store_e2e_rx`. Usunięto `sf::ACTIVE/ACK_SEQ/NEXT_SEQ/WINDOW/KEYS/SEQ`. Weryfikacja: lithiumd 114 (w tym gc/ack/roundtripy), `ds_messaging` 6, `ds_invite_abuse` 5.

Łącznie usunięte martwe `sf` (przejęte przez serde): `SEEN_AT_MS, UPDATED_AT_MS, CREATED_AT_MS, TS_MS, MODE, KIND, RX_USED, TX_USED, RETIRE_OK, RETIRED_AT_MS, ACTIVE, ACK_SEQ, NEXT_SEQ, WINDOW, KEYS, SEQ` (16) + metoda `E2eMode::as_str`.

Domknięcie residual §8 (literały-klucze pominięte przez GRUPA A, ta sesja):
- `contact_mailbox.rs` — WSZYSTKIE `get_str(v, "literal")` -> `get_str(v, sf::*)` (perl: nazwa stałej = uppercase wartości) + test `.remove("mbox_out_next_priv")` -> `sf::MBOX_OUT_NEXT_PRIV`.
- `crypto.rs` — `json_get_str(peer_obj, "ed_pub"/"dili_pub")` (odczyt kluczy peera do weryfikacji podpisu) -> `sf::ED_PUB/DILI_PUB`.
- `state_self.rs` — `drop_removed_json_key(obj, "x_priv"/"k_priv")` -> `sf::X_PRIV/K_PRIV`.
- ŚWIADOMIE ZOSTAJĄ literałami (nie pozycja klucza): `json_missing_field("...")` etykiety błędów (utrwalony wzorzec klucz=sf/etykieta=literał), wartości trybów (`"bootstrap"`/`"text"`), klucze wyjścia IPC `"mailbox_gen"` w `json!` (warstwa IPC, odłożona), golden-piny (`header.rs`/`stored_message.rs`), `"recovered"` (ui-meta IPC).
- Weryfikacja: lithiumd 114 + clippy + `ds_messaging` 6 (ścieżka weryfikacji podpisu w crypto.rs pokryta).

8. `SelfMailbox {tx_gen,tx_sent,rotate_every}` + `PeerMailbox {peer_tx_gen_seen, sender_pubs:BTreeMap<String,String>}` — w `contact_mailbox.rs` (NIE state.rs: warstwa command, `MAILBOX_ROTATE_EVERY_DEFAULT` tutaj; BEZ zeroize — sender_pubs to klucze publiczne, self to liczniki). Helpery `load/store_self_mailbox`, `load/store_peer_mailbox`. Skonwertowane WSZYSTKIE funkcje: `ensure_mailbox_state` (self+peer init przez load/store, sender_pubs 0/1 przez `.entry().or_insert()`), `peer_store_mailbox_sender_keys`, `peer_sender_pub_for_generation`, `self_tx_generation`, `mark_outbound_message_sent` (rotacja), `note_inbound_generation_seen`, `inbound_fetch_generations`. Usunięto helpery `sender_pub_map`/`_mut`. ~50 asercji testowych skonwertowanych (helpery `set_rotate`/`set_peer_mailbox` w mod tests; reads przez `load_*_mailbox`). Usunięto `sf::TX_GEN/TX_SENT/ROTATE_EVERY/PEER_TX_GEN_SEEN/SENDER_PUBS`. UWAGA `gen` to słowo zarezerwowane w edition 2024 (zmienna `cur_gen`). UWAGA: §7.4 — `peer.mbox_out_cur/next_pub` setter wciąż ×3 (peer_store/note_inbound/ensure), nie zdedup (drobne). Weryfikacja: lithiumd 114, `ds_messaging` 6 (rotacja generacji), `ds_invite_abuse` 5.

Łączny stan §6: rejestr `sf` 55 -> 30 stałych. Wszystkie POD-DOKUMENTY stanu (e2e_rx, e2e_peer, bootstrap, mailbox self+peer, prekeys_remote, msg-meta, prekey-public) są typowanymi serde-structami; produkcja nie ma już ad-hoc `json!`/Value-poke pól stanu ratcheta/mailboxa.

ZOSTAŁE 30 stałych `sf` (NIE są ad-hoc state-poke, inny charakter):
- klucze KONTENERÓW koperty: `E2E_RX, E2E_TX, E2E_PEER, BOOTSTRAP, MAILBOX, PEER, NEED_RECOVER, PREKEYS_LOCAL_PUBLIC/ADVERTISED/REMOTE, LABEL` — nieodłączne dopóki `self_v`/`peer_v` to `SecretJson(Value)` envelope; znikną dopiero z pełnymi kontenerami.
- pola TOŻSAMOŚCI/kluczy (§7.3, nie §6): `CID, X_PUB, K_PUB, ED_PUB, DILI_PUB, X_PRIV, K_PRIV, ED_PRIV, DILI_PRIV, MBOX_IN/OUT_*` — czytane pole-po-polu (część zrobiona przez `invite_public_from_self`); docelowo `PeerIdentity` struct.
- drobne: `ID` (prekey/e2e_peer id), `STEP` (e2e_tx + e2e_peer.step read w session:79), `MSG_ID`/`MAILBOX_GEN` (ui-meta read w contact_fetch).

ZOSTAJE (opcjonalnie, osobny duży przebieg):
- Pełne kontenery `SelfState`/`PeerState` zamiast `SecretJson(Value)` na granicy storage — usuwa klucze-kontenery; dotyka WSZYSTKICH command-handlerów (load/save) + sygnatur funkcji e2e (z `&mut Value`/`SecretJson` na typy) + IPC. NAJWIĘKSZY/najryzykowniejszy, robić jako dedykowany przebieg.
- §7.3 reszta: `PeerIdentity`/`SelfIdentity` struct dla pól tożsamości (cid/x/k/ed/dili/mbox_*) zamiast pole-po-polu (`ensure_self_keyring`, `self_bootstrap_rx_privs`, `crypto.rs` peer-id reads, `contact_mailbox.rs` identity reads, `derive_mailboxes`).
- bootstrap `{rx_used,tx_used,retire_ok,retired_at_ms}` — `state_self.rs`/`state_peer.rs`.
- meta/ui json! (`{ts_ms,msg_id,kind,step,mode,mailbox_gen}`) zwracane z encrypt/decrypt — struct `MsgMeta`.
- mailbox `{tx_gen,tx_sent,rotate_every,peer_tx_gen_seen,sender_pubs{<gen>:{...}}}` — `contact_mailbox.rs` (307 linii, §7.4 zapisy kluczy nadawcy też tu). NAJWIĘKSZY kawałek.
- crypto.rs rekonstrukcja nagłówka (już używa typowanego SignedHeader z header.rs — sprawdzić co zostało).
- Docelowo: pełne kontenery `SelfState`/`PeerState` zamiast `SecretJson(Value)` na granicy storage — ostatni krok, dotyka wszystkich command-handlerów ładujących/zapisujących stan.

### J. §6-FINAL — pełne kontenery `SelfState`/`PeerState` (ta sesja, niezacommitowane)
Decyzja usera: pełne structy + `ZeroizeOnDrop` (mocniejsza gwarancja zeroizacji niż best-effort przejazd po `SecretJson(Value)`). `SecretJson(Value)` USUNIĘTY z całej ścieżki stanu kontaktu.
- NOWE w `e2e/state.rs`: `SelfState`, `PeerState` (oba `#[derive(Serialize, Deserialize, Zeroize)]` + ręczny `impl Drop { self.zeroize() }`), `PeerIdentity`, `E2eTx`, `SelfMailbox`, `PeerMailbox`. `from_bytes`/`to_secret_bytes` na granicy storage. `peer_is_set()`.
- ZEROIZACJA: `String` (hex) zeroizowane przez derive; `E2eRx`/`PeerMailbox` mają RĘCZNY `impl Zeroize` (BTreeMap nie ma derive) drenujący mapę — klucze ORAZ wartości, jak stary `SecretJson::zeroize_value`. `RxKey` dalej `ZeroizeOnDrop`. `drop_bootstrap_private_if_established` jawnie `take()+zeroize()` na `x_priv`/`k_priv` (Option) przy retirementcie.
- Sygnatury e2e/command z `&mut Value`/`&mut SecretJson` -> `&mut SelfState`/`&mut PeerState` w: `state_self.rs`, `state_peer.rs`, `crypto.rs`, `prekeys.rs`, `session.rs`, `contact_mailbox.rs`. `ensure_mailbox_state` przyjmuje już tylko `&mut PeerState` (self gwarantowany przez typy/serde-default; legacy-fallbacki z x_priv usunięte — brak deploymentu).
- Handlery (granica storage) na `*State::from_bytes`/`to_secret_bytes`: `contact_send`, `contact_fetch`, `invite_create`, `invite_accept`, `contact_verify_emoji`, `contact_list`. `gen_self_state` zwraca `(Vec<u8>, SelfState)`. `invite_public_from_self(&SelfState)`. ui-meta dekodowane typowo przez `MsgMeta` (zamiast literałów `mailbox_gen`/`msg_id`).
- USUNIĘTE martwe: `state_fields.rs` (cały rejestr `sf::*` zbędny — nazwy trzyma serde), `mod state_fields` w `main.rs`, `wire::drop_removed_json_key`, struct `SelfStateSerde`/`EmptyPeerState`/`PeerStatePeer`/lokalne `SelfMailbox`/`PeerMailbox`.
- KANON BEZ ZMIAN: `SignedHeader::canonical_bytes()` nietknięty — reprezentacja stanu nigdy nie dotyka bajtów wire/podpisu. On-disk format stanu zmieniony świadomie (brak deploymentu).
- WERYFIKACJA (cała zielona): lithiumd 111 (w tym round-tripy `state::tests::*`, SAS, ratchet/gc/ack/prekey), clippy `--tests` czysto, core 9 + store/crypto, lithiums 32. Integracje: `ds_messaging` 6, `ds_invite_abuse` 5, `ds_account_lifecycle` 5, `ds_concurrent` 3, `daemon_basic` 7, `daemon_server` 4, `daemon_contacts` 4.

STATUS INWENTARZA: wszystkie pozycje §1-§11 z `hardening.md` ZROBIONE. Zostaje tylko opcjonalne, niskie-pri: §13 `key_type`->enum (KT_* wchodzą w AAD keyfile, ryzyko, pominięte) i rejestr pól warstwy IPC (`lithiumg`<->`lithiumd`, cross-crate).

## Uwagi stylu (przypomniane przez usera)
- Komentarze tylko „dlaczego", nigdy „co"; minimum, tylko gdzie naprawdę niezbędne; reszta ma czytać się z kodu; bez dekoracyjnych dividerów; bez znaków spoza klawiatury. (Patrz CLAUDE.md / pamięć `feedback_code_style`.)
- Goldeny krypto = realny output (decrypt/verify), bez ręcznie wpisanych nonce; format-pliki z materiałem klucza (keyfile/identity/mkfile) = syntetyczne.
