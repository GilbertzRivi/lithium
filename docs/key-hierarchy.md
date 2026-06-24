# Katalog i hierarchia kluczy

Jeden zbiorczy widok wszystkich kluczy i sekretów w Lithium: skąd pochodzą, gdzie leżą, jak długo żyją i co chronią. Szczegóły derywacji opisuje [crypto-protocol.md](crypto-protocol.md); konsekwencje dla bezpieczeństwa — [security-model.md](security-model.md). Wszystkie etykiety są pinowane testami (`registry_values_are_pinned`).

## Drzewo zależności

```
data_password ─┬─ Argon2id(·, salt z mk.enc) ─→ klucz odczytu MK ─→ MK ─→ KEK = HKDF(MK, salt, "kek/v1") ─→ DEK(.keyf) ─→ klucze prywatne / sekrety
               └─ Argon2id(·, root.salt) ─→ password_root ─┐
                                                            ├─ HKDF(server_dek, salt=password_root, "…/combined/v1") ─→ combined_root ─→ db_dek ─→ lokalny SQLite
serwer (login OPAQUE) ─→ server_dek ────────────────────────┘     (server_dek owinięty pod export_key OPAQUE, AAD "lithium/dek-wrap/v1")

server MK ─→ KEK ─→ DEK(.keyf serwera) ─→ klucze tożsamości serwera
          └─ derive_secret32 ─→ { db_dek serwera ("lithium/db-dek/v1") → pola users, jwt-secret ("lithium/jwt-secret/v1") }
msg_key (losowy per wiadomość, tylko RAM, TTL 24 h) ─→ treść wiadomości w DB serwera
```

Kluczowa właściwość: `db_dek` klienta wymaga **jednocześnie** `password_root` (z hasła danych) i `server_dek` (z serwera). Utrata jednego z czynników uniemożliwia odszyfrowanie lokalnej bazy — to celowy dwuczynnik.

## Klient — szyfrowanie danych w spoczynku

| Klucz | Typ | Derywacja / źródło | Przechowywanie | Czas życia / rotacja | Chroni |
|-------|-----|--------------------|----------------|----------------------|--------|
| Master Key (MK) | 32 B losowy | opakowany `AES-256-GCM-SIV(MK, Argon2id(data_password, salt), aad="lithium/mkfile/v1")` | `keystore/user/mk.enc` | rotacja co 1 h (`MkRotator`, tick 30 s) | wszystkie pliki `.keyf` (przez KEK) |
| KEK | 32 B | `HKDF(MK, salt_pliku, info="kek/v1")` | nie przechowywany (derywowany przy użyciu) | wraz z MK | opakowanie DEK w `.keyf` |
| DEK pliku `.keyf` | 32 B losowy | losowy per plik | w `.keyf`, opakowany pod KEK | rewrap przy rotacji MK (wartość bez zmian) | payload klucza/sekretu w pliku |
| root.salt | 32 B losowy | losowy per instalacja | `keystore/user/root.salt` | stały | sól dla `password_root` |
| password_root | 32 B | `Argon2id(data_password, root.salt)` (64 MiB, t=3, p=1) | tylko RAM (cache) | sesja (do `lock_keystore`) | wejście do `combined_root` |
| server_dek | 32 B losowy | losowy przy `register`; owinięty pod `export_key` OPAQUE (AAD `"lithium/dek-wrap/v1"`) | **na serwerze**; zwracany przy login; nigdy na dysku klienta | do usunięcia konta | wejście do `combined_root` |
| combined_root | 32 B | `HKDF(server_dek, salt=password_root, info="lithium/user-provider/combined/v1")` | tylko RAM | sesja | źródło `db_dek` |
| db_dek (klient) | 32 B | `HKDF(combined_root, info="lithium/db-dek/v1")` | tylko RAM | sesja | pola `*_enc` w lokalnym SQLite |
| export_key (OPAQUE) | wyjście OPAQUE | wyprowadzany klient-side przy register/login | tylko RAM | per operacja | owija `server_dek` |

## Klient — klucze per kontakt

Przechowywane w `self_state` / `peer_state`, zaszyfrowane `db_dek` (AAD `lithiumd/contact-self/v1` / `lithiumd/contact-peer/v1`). Każdy kontakt ma niezależny zestaw — kompromitacja jednego nie dotyka innych.

| Klucz | Typ | Źródło | Czas życia / rotacja | Rola |
|-------|-----|--------|----------------------|------|
| Szyfrowanie E2E | X25519 + ML-KEM-1024 | losowe przy `create_invite` | trwałe per kontakt | KyberBox treści E2E |
| Podpisy E2E | Ed25519 + ML-DSA-87 | losowe przy `create_invite` | trwałe per kontakt | dual-podpis wiadomości E2E |
| Klucze mailbox | 3× X25519 (in / out_cur / out_next) | losowe przy `create_invite` | `out` rotowane co 32 wysłania | adresowanie skrzynek |
| Bootstrap | X25519 + ML-KEM (z kodu `lci1:`) | z zaproszenia | usuwane po ack peera + ratchecie | pierwsza wiadomość do kontaktu |
| RX keyring (reply) | X25519 + ML-KEM per wysłanie | świeże per send, numerowane `seq` | okno 32 od `ack_seq`; starsze kasowane (zeroize) | ratchet kluczy odpowiedzi |
| Prekeys | 5× X25519 + ML-KEM | generowane przy 1. wysłaniu; prywatne w tabeli `prekeys` (AAD `lithiumd/prekey/v1`) | usuwane po użyciu (`take_prekey`) | recovery po desynchronizacji |

## Transport (klient ↔ serwer)

| Klucz | Typ | Źródło | Przechowywanie / TTL | Rola |
|-------|-----|--------|----------------------|------|
| Tożsamość serwera (długoterminowa) | X25519 + ML-KEM (enc) + Ed25519 + ML-DSA (sign) | `KeyManager` serwera; część publiczna pinowana u klienta w `server.identity` | trwałe | Shake, podpis odpowiedzi serwera |
| Klucze sesji transportowej | X25519 + ML-KEM efemeryczne | generowane przez serwer po każdej odpowiedzi | `EphemeralStore`; TTL 60 s (Shake) / 120 s (Session) | szyfrowanie kolejnych żądań |
| Efemeryczne klucze klienta | X25519 + ML-KEM + Ed25519 + ML-DSA | per żądanie (endpointy `KeysInHeaders`) | tylko na czas żądania | anonimowy transport (shake / send / fetch / revoke) |

## Serwer

| Klucz | Typ | Derywacja / źródło | Przechowywanie | Rotacja | Chroni |
|-------|-----|--------------------|----------------|---------|--------|
| Server MK | 32 B | `TpmMkProvider` (sealed KEYEDHASH) lub `PlainFileMkProvider` | blob TPM (`LITHIUM_TPM_SEALED_PATH`) lub plik | co 1 h | pliki `.keyf` serwera |
| Server db_dek | 32 B | `derive_secret32("lithium/db-dek/v1")` z server MK | tylko RAM | wraz z MK (rewrap) | pola tabeli `users` |
| msg_key (per wiadomość) | 32 B losowy | losowy przy `add_message` | `EphemeralStore`, TTL 24 h | jednorazowy (`store.take` przy fetch) | treść wiadomości na serwerze (AAD `message-content/v1` ‖ mailbox) |
| JWT secret | 32 B | `derive_secret32("lithium/jwt-secret/v1")` | tylko RAM | regenerowany przy rotacji MK | podpis HS256 tokenów JWT |
| OPAQUE ServerSetup | setup OPAQUE | generowany; sealed (label `lithium/opaque-server-setup/v1`) | sealed blob | trwały | uwierzytelnianie OPAQUE wszystkich kont |
| TPM sealing parent | ECC P-256 (restricted decryption) | deterministycznie z owner seed TPM | **nigdy nie persystowany** | — | rodzic pieczętujący Server MK |

`db_dek` klienta i serwera używają tej samej etykiety `"lithium/db-dek/v1"`, ale wychodzą z **różnych** providerów MK (klient: `combined_root`; serwer: server MK) — to dwa różne klucze.

## Analiza wycieku

Co odsłania kompromitacja danego elementu:

| Kompromitacja | Co odsłonięte | Co nadal chronione |
|---------------|---------------|--------------------|
| Sam dysk klienta (bez hasła) | nic — `.keyf` i SQLite zaszyfrowane; MK za Argon2 | wszystko |
| Dysk klienta + hasło danych, **bez** serwera | MK i klucze `.keyf` odtwarzalne | lokalna baza (brak `server_dek` → brak `db_dek`) — celowy dwuczynnik |
| Dysk + hasło + aktywna sesja z serwerem | pełne dane tego użytkownika | (model zakłada, że to sam użytkownik) |
| Wyciek `db_dek` z RAM | lokalna baza póki klucz żyje | MK, klucze `.keyf` |
| Przejęcie serwera relay | zaszyfrowane pola `users` i zaszyfrowane skrzynki | treści E2E (klucze per-kontakt tylko u klientów); restart niszczy `msg_key` → zaległe wiadomości trwale nieodszyfrowalne |
| Klucze jednego kontaktu | ten jeden kontakt | pozostałe kontakty (izolacja) |
| Złamanie ML-KEM **albo** X25519 osobno | nic — druga połowa hybrydy nadal chroni | treści (potrzebne złamanie obu) |
