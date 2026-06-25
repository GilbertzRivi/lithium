# Cykl życia danych i inwentarz prywatności

Jeden widok: jakie dane istnieją, gdzie spoczywają (RAM / dysk klienta / serwer / sieć), jak długo żyją i kto może je zobaczyć. Uzupełnia [security-model.md](security-model.md) („co serwer widzi per request") i [key-hierarchy.md](key-hierarchy.md) (klucze). Aktorzy w całym dokumencie: **użytkownik**, **daemon klienta** (`lithiumd`, ma plaintext gdy odblokowany), **serwer relay** (`lithiums`, wrogi), **obserwator sieci** (pasywny), **operator reverse proxy** (terminuje TLS), **kontakt** (sparowany peer).

## Inwentarz danych

| Dane | Gdzie spoczywa | Forma / ochrona | Retencja |
|------|----------------|------------------|----------|
| Treść wiadomości (plaintext) | tylko RAM klienta (komponowanie/wyświetlanie) | brak — żywy plaintext | ulotna; nigdy na dysku w plaintext |
| Treść wiadomości (lokalna historia) | dysk klienta — `storage/lithiumd.sqlite` | AES-256-GCM-SIV pod `db_dek` (AAD `lithiumd/message/v1`) | do `contact_forget` / `wipe_local` |
| Treść wiadomości (w tranzycie/na serwerze) | drut → serwer (PostgreSQL `messages`) | E2E (KyberBox) + dodatkowa warstwa serwera (`msg_key`) | na serwerze do pierwszego fetchu (one-time) lub TTL 24 h |
| Stan kontaktu / klucze per-kontakt | dysk klienta — SQLite (`contacts`) | AES-256-GCM-SIV pod `db_dek` (AAD `contact-self/v1`/`contact-peer/v1`) | do `contact_forget` / `wipe_local` |
| Adres skrzynki (mailbox) | w zaszyfrowanym ciele żądania; serwer w `messages.mailbox` | pseudolosowe 32 B; niepowiązane z tożsamością | jak wiadomość |
| Handler (nazwa użytkownika) | serwer (jako deterministyczne `id_enc`) | UUID v5 → AES-256-GCM-SIV; brak plaintextu | do `delete_account` |
| Hasło konta / hasło danych | tylko RAM klienta (`SecretString`) | zeroizowane przy `lock_keystore`; nigdy na dysk ani do serwera | sesja |
| `server_dek` | serwer (`users.dek`) | owinięty pod `export_key`, potem AAD `user-dek/v1` | do `delete_account` |
| Lokalne klucze (`.keyf`: MK, tożsamość, sekrety) | dysk klienta — `keystore/` | payload pod DEK, DEK pod KEK (z MK); MK pod Argon2(hasło) | trwałe (do `wipe_local`) |
| Rekord użytkownika (opaque, ed/dili, dek) | serwer (`users`) | każde pole AES-256-GCM-SIV pod server `db_dek`, osobny AAD | do `delete_account` |
| `db_dek` / `password_root` / `combined_root` / `dek_plain` | tylko RAM (klient i serwer) | derywowane na żądanie | sesja (do `lock`) |
| Klucze sesji transportowej | RAM serwera (`EphemeralStore`) | efemeryczne | TTL 60 s (Shake) / 120 s (Session) |
| `msg_key` (klucz per wiadomość) | RAM serwera (`EphemeralStore`) | losowy 32 B | TTL 24 h; ginie przy restarcie serwera |
| JWT | RAM serwera (`EphemeralStore`) + RAM klienta | HS256, jednorazowy (`store.take`) | TTL sesji 120 s |
| Liczniki rate-limit / hasze replay | RAM serwera (`EphemeralStore`) | — | okna 10 s / 15 min / 1 h; replay 600 s |
| `server.identity` / `server_url` / `registered.flag` | dysk klienta | klucze publiczne / URL / marker — niewrażliwe | trwałe |
| Metadane sieciowe (IP, czas, wolumen) | u proxy / obserwatora | TLS; padding rozmiarów; cover traffic | poza Lithium (logi operatora) |

## Życie wiadomości (hop po hopie)

```
[1] Nadawca pisze plaintext          → tylko RAM daemona nadawcy
[2] contact_send: szyfrowanie E2E    → WireV1 (KyberBox), zapis lokalny (outbound, db_dek)
[3] Transport do serwera             → KyberBox transportu w slocie cover traffic; PoW
[4] Serwer odbiera                   → widzi adres skrzynki + szyfrogram E2E; owija msg_key; zapis w `messages`
[5] Odbiorca auto-fetch (w tle)      → pobranie + atomowe usunięcie (one-time); msg_key zużyty
[6] Daemon odbiorcy deszyfruje       → weryfikacja dual-podpisu, zapis lokalny (inbound, db_dek)
[7] GUI odbiorcy wyświetla           → plaintext tylko w RAM
```

Na żadnym hopie sieciowym (3) ani na serwerze (4) treść nie jest czytelna — E2E jest niezależne od transportu, a serwer nie ma kluczy per-kontakt.

## Co spoczywa gdzie

**Dysk klienta** (`{data_dir}`, `0o700`): `keystore/` (`.keyf` opakowane MK, `mk.enc` pod Argon2(hasło), `root.salt`), `storage/lithiumd.sqlite` (kontakty/wiadomości/prekeys — blobi pod `db_dek`), `server.identity` (publiczne), `server_url`, `registered.flag`. **Nigdy** w plaintext: treści, kluczy prywatnych, hasła.

**RAM klienta** (odblokowany): hasło danych i konta, `dek_plain`, `password_root`, MK, klucze per-kontakt w użyciu, plaintext wyświetlanej wiadomości. Zeroizowane przy `lock_keystore`.

**Dysk serwera**: PostgreSQL (`users` — pola zaszyfrowane pod server `db_dek`, poza deterministycznym `id_enc`; `messages` — treść podwójnie zaszyfrowana), keystore serwera (`.keyf`), zapieczętowany blob MK (TPM). **Nie ma**: hasła, kluczy E2E, plaintextu treści.

**RAM serwera** (`EphemeralStore`): prywatne klucze sesji, `msg_key`, JWT, liczniki rate-limit, hasze replay. Restart czyści wszystko → zaległe wiadomości trwale nieodszyfrowalne.

**Drut / reverse proxy**: proxy terminuje TLS i widzi jawne nagłówki HTTP (efemeryczne klucze publiczne, identyfikatory sesji, `seed`, podpisy) oraz **zaszyfrowane** ciało (KyberBox do kluczy serwera) — nie odczyta treści ani nawet plaintextu transportu. Dodatkowo widzi IP klienta, czasy i rozmiary (dopełnione do bloków 32–64 KB / 4–8 KB). Pasywny obserwator przed proxy widzi tylko ruch TLS do relaya.

## Retencja — skrót

| Element | Czas życia |
|---------|-----------|
| Plaintext treści (RAM klienta) | ulotny |
| Sekrety w RAM (hasło, `db_dek`, klucze) | do `lock_keystore` |
| Klucze sesji transportowej | 60 s / 120 s |
| JWT | 120 s, jednorazowy |
| `msg_key` + wiadomość na serwerze | do pierwszego fetchu lub 24 h |
| Replay body-hash | 600 s |
| Lokalna historia / kontakty / klucze `.keyf` | do `forget` / `wipe_local` |
| Rekord użytkownika + `server_dek` | do `delete_account` |

## Kto co widzi

| Dane | Użytkownik | Daemon (odblok.) | Serwer | Obserwator/Proxy | Kontakt |
|------|-----------|------------------|--------|------------------|---------|
| Treść wiadomości | tak | tak | **nie** | **nie** | tak (to co wysłane jemu) |
| Z kim koresponduje | tak | tak | **nie** (adresy pseudolosowe) | **nie** | tylko siebie |
| Handler użytkownika | tak | tak | **nie** (tylko `id_enc`) | **nie** | tak (peera, po parowaniu) |
| Hasło | tak | tak (RAM) | **nie** | **nie** | **nie** |
| Fakt łączenia z relayem | tak | tak | tak | tak (IP/czas) | **nie** |
| Czas/wolumen realnego ruchu | tak | tak | częściowo (skrzynki) | **nie** (cover traffic) | **nie** |
