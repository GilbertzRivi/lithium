# Pre-Audit Hardening Checklist — Lithium

**Date**: 2026-03-09
**Purpose**: Lista rzeczy do naprawienia/usunięcia przed oddaniem repozytorium zewnętrznemu
audytorowi. Każdy punkt z tej listy zostanie wychwycony przez audytora i wywoła pytania lub
obniży ocenę. Wiele z nich to "instant red flags" które nie wymagają głębiej analizy.

---

## BLOKUJĄCE — napraw przed oddaniem

### B-1: Dane uwierzytelniające i rzeczywiste klucze w `.env` zacommitowane do repozytorium

**Pliki**: `lithiums/.env`, `lithiumd/.env`, `lithiumg/.env`

`lithiums/.env` zawiera hasło do bazy danych w plaintext:
```
DATABASE_URL=postgres://lithium:Tomeczek1PG@127.0.0.1:5556/lithium
```

`lithiumd/.env` zawiera pełne klucze kryptograficzne serwera (X25519, Kyber, Ed25519, ML-DSA-87)
jako wartości hex w plaintext. Te klucze prawdopodobnie są/były używane na prawdziwej instancji.

Audytor natychmiast wyszuka w historii git wszelkie credentials i klucze. Jeśli te pliki są w
historii, nawet po usunięciu, klucze należy uznać za skompromitowane.

**Do zrobienia**:
1. Dodaj `.env` do `.gitignore` (jeśli jeszcze nie ma)
2. Utwórz `.env.example` z placeholder wartościami
3. **Obróć wszystkie klucze** które pojawiły się w `.env` — wygeneruj nowe klucze serwera
4. Rozważ `git filter-repo` lub BFG Repo Cleaner do wyczyszczenia historii

---

### B-2: `RUST_LOG=debug` w konfiguracji produkcyjnej serwera

**Plik**: `lithiums/.env`

```
RUST_LOG=debug
```

Z włączonym debug-logowaniem, w `transport/mod.rs` logowane są nazwy pól zdekryptowanego
request body (line 378):
```rust
debug!(
    body_keys = ?body_keys,
    app_header_keys = ?header_keys,
    "parsed decrypted json"
);
```

Oraz w `api/user.rs` (line 32) username przy każdej rejestracji:
```rust
debug!(handler = %handler.expose(), ...);
```

W środowisku produkcyjnym poziom logowania powinien być `warn` lub `error`. Każdy audytor
sprawdzi co trafia do logów.

**Do zrobienia**: Zmień na `RUST_LOG=warn` w `.env.example` i dokumentacji deploymentu.

---

### B-3: Komenda `wipe_local` nie kasuje danych — tylko usuwa wpisy katalogowe

**Plik**: `lithiumd/src/util.rs`, linia 133–138

```rust
pub fn wipe_dir_all(p: &Path) -> std::io::Result<()> {
    if p.exists() {
        fs::remove_dir_all(p)?;   // unlink — nie nadpisuje danych!
    }
    Ok(())
}
```

`fs::remove_dir_all` usuwa tylko wpisy katalogowe z systemu plików. Zawartość bloków
(klucze prywatne, baza SQLite z blobami `self_state`, prekeys, treść wiadomości) pozostaje
na dysku do momentu gdy system plików naturalnie nadpisze te bloki — co na SSD z
wear-levelingiem może nigdy nie nastąpić w sposób deterministyczny.

**Dlaczego to jest blokujące przed audytem**: Audytor **zawsze** sprawdza funkcję "wipe"/"delete account" jako jeden z pierwszych testów. Jeśli po wywołaniu `wipe_local` dane są odzyskiwalne (co jest tutaj w 100% przypadek), raport audytu będzie zawierał krytyczny finding z nagłówkiem "Data not securely erased".

Klucze prywatne są co prawda zaszyfrowane (AES-256-GCM-SIV pod MK), ale SQLite zawiera `self_state` blobs z kluczami prywatnymi w hex (finding H-4/Z-2), które są dostępne po odszyfrowaniu za pomocą DEK. Sama baza danych zawiera też prekey blobs i zaszyfrowane wiadomości.

**Do zrobienia**:
1. Przed `fs::remove_file` dla każdego pliku kluczowego: otwórz plik, nadpisz zerami, `fsync`, zamknij, a potem usuń
2. Dla SQLite: wyczyść wrażliwe pola (`self_state`, `peer_state`, `blob`) przed usunięciem (`UPDATE contacts SET self_state = '', peer_state = ''`, potem `VACUUM`)
3. Udokumentuj że na SSD (ze względu na wear-leveling) bezpieczne kasowanie jest trudne i zaproponuj alternatywę: key-erasure (usuń tylko MK — bez MK reszta jest niedostępna)

---

### B-4: Zero testów dla prymitywów kryptograficznych

W całym repozytorium nie ma ani jednego pliku testowego (poza autogenerowanymi przez biblioteki
w `target/`). Brak testów dla:
- Round-trip `encrypt`→`decrypt` dla każdego prymitywu
- Weryfikacji podpisów ed25519/ML-DSA
- Weryfikacji że fałszywe dane nie przechodzą AEAD
- KyberBox encrypt/decrypt
- Keyfile save/load z poprawnym i błędnym kluczem
- Derive mailbox — determinizm, directionality
- DEK wrap/unwrap
- Padding/unpadding

Audytor zapyta: "skąd wiecie że to działa poprawnie?" Brak testów jest bezpośrednim
wskaźnikiem że kod nie był systematycznie weryfikowany.

**Do zrobienia**: Napisz minimum testy round-trip dla każdego modułu w `lithium_core/src/crypto/`.
Przynajmniej:
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_aead_round_trip() { ... }
    #[test]
    fn test_aead_wrong_key_fails() { ... }
    #[test]
    fn test_kyberbox_round_trip() { ... }
    #[test]
    fn test_sign_verify() { ... }
    #[test]
    fn test_sign_tampered_fails() { ... }
}
```

---

### B-5: Pre-release / Release Candidate dependencies dla kodu kryptograficznego

**Plik**: `lithium_core/Cargo.toml`

```toml
aes-gcm-siv = "0.12.0-rc.3"          # RC!
argon2 = { version = "0.6.0-rc.1" }  # RC!
ed25519-dalek = "3.0.0-pre.6"         # PRE-RELEASE!
x25519-dalek = "3.0.0-pre.6"          # PRE-RELEASE!
```

Używanie pre-release i RC wersji bibliotek kryptograficznych w produkcyjnym kodzie to
natychmiastowy red flag dla każdego audytora. Pre-release wersje mogą mieć nieudokumentowane
API changes, niezałatane CVE lub niezamierzone zmiany zachowania.

Dodatkowo: `lithium_core` używa `argon2 = "0.6.0-rc.1"` a `lithiumd` używa `argon2 = "0.6.0-rc.7"` —
dwie różne wersje tej samej biblioteki kryptograficznej w ramach jednego projektu.

**Do zrobienia**:
- Poczekaj na stabilne release ww. bibliotek (lub użyj starszych stabilnych wersji)
- Ujednolic wersje `argon2` między crateami przez workspace-level dependency
- Jeśli pre-release są niezbędne, udokumentuj dlaczego i który commit/hash jest pinned

---

### B-6: Brak jawnych feature flag `zeroize` na bibliotekach kryptograficznych

**Plik**: `lithium_core/Cargo.toml`

```toml
ed25519-dalek = { version = "3.0.0-pre.6" }  # brak features = ["zeroize"]
x25519-dalek = { version = "3.0.0-pre.6", features = ["static_secrets"] }  # brak "zeroize"
aes-gcm-siv = "0.12.0-rc.3"  # brak features = ["zeroize"]
argon2 = { version = "0.6.0-rc.1" }  # brak features = ["zeroize"]
```

Bez jawnie zadeklarowanego `features = ["zeroize"]`, zeroizacja kluczy po użyciu może nie
działać — zależy od domyślnych feature flag konkretnej wersji. Audytor musi to zweryfikować
dla każdej wersji osobno. Jawna deklaracja eliminuje wątpliwości.

**Do zrobienia**:
```toml
ed25519-dalek = { version = "...", features = ["zeroize"] }
x25519-dalek  = { version = "...", features = ["static_secrets", "zeroize"] }
aes-gcm-siv   = { version = "...", features = ["zeroize"] }
argon2        = { version = "...", features = ["zeroize"] }
```

---

## WYSOKIE — napraw przed audytem

### H-1: Zakomentowany kod w `main.rs` (wygląda jak debug artifact)

**Plik**: `lithiums/src/main.rs`, linie 111–122

```rust
// let pk = {
//     let guard = key_manager.lock().await;
//     guard.public_keys().clone()
// };
//
// info!(
//     "PublicKeys {{ ed25519: {}, x25519: {}, kyber: {}, dilithium: {} }}",
//     hex::encode(pk.ed25519.as_slice()),
//     ...
// );
```

Zakomentowany kod sugeruje audytorowi że był tu debug/diagnostic kod który "na razie" jest
wyłączony. Jeśli logowanie kluczy publicznych ma sens (np. przy starcie serwera jako kontrola),
niech będzie aktywne i poprawnie sformatowane. Jeśli nie — usuń całkowicie.

**Do zrobienia**: Usuń zakomentowany blok lub odkomentuj z poprawnym użyciem `tracing`.

---

### H-2: Serwer uruchamia się bez TLS, brak dokumentacji wymagań deploymentu

**Plik**: `lithiums/src/main.rs`, linia 132

```rust
Server::new(TcpListener::bind(bind)).run(app).await
```

Serwer nasłuchuje na TCP bez TLS. Protokół aplikacyjny jest szyfrowany (KyberBox), ale
warstwa transportu jest plaintextowa. Audytor zapyta: "czy to jest bezpieczne bez TLS?"
Technicznie tak (jeśli aplikacyjna kryptografia jest poprawna), ale wymaga uzasadnienia.

**Do zrobienia**: Dodaj w README/dokumentacji wyraźną sekcję: "serwer wymaga TLS-terminating
reverse proxy (nginx/caddy) — nie uruchamiaj bez TLS w środowisku produkcyjnym".

---

### H-3: Wiadomości są nie do odzyskania po restarcie serwera

**Plik**: `lithiums/src/db/repo.rs`, `add_message` i `get_messages`

Architektura: wiadomości szyfrowane są losowym `msg_key: Byte32`. Klucz przechowywany jest
tylko w `EphemeralStoreManager` (pamięć RAM) z TTL 24h. Zaszyfrowana wiadomość zapisywana jest
do bazy danych. Przy restarcie serwera EphemeralStore jest czyszczone — klucze przepadają,
a wiadomości w DB są nieodszyfrowane na zawsze.

Jest to przemyślana decyzja (forward secrecy wiadomości na poziomie serwera), ale musi być
jawnie udokumentowana jako właściwość systemu, a nie wyglądać jak bug.

**Do zrobienia**: Dodaj komentarz w kodzie i dokumentacji wyjaśniający tę właściwość.
Rozważ ostrzeżenie podczas startu ("jeśli serwer był restarted, wiadomości starsze niż X
mogą być niedostępne").

---

### H-4: Nieużywane importy/dependencje w Cargo.toml

**Plik**: `lithium_core/Cargo.toml`

```toml
base64 = "0.22.1"   # nie widać użycia w przejrzanym kodzie
hmac = "0.12"       # nie widać użycia w lithium_core (używany w lithiums)
```

Nieużywane zależności w projekcie kryptograficznym budzą pytania: "po co to jest?" lub
"czy to było usunięte ale zależność została?" Audytor sprawdza każdą zależność kryptograficzną.

**Do zrobienia**: Uruchom `cargo machete` lub `cargo udeps` i usuń nieużywane zależności.

---

### H-5: Handler (username) logowany w plaintext przy rejestracji

**Plik**: `lithiums/src/api/user.rs`, linia 32 i 51 (warn)

```rust
debug!(handler = %handler.expose(), ...)  // linia 32 — debug
warn!(handler = %handler.expose(), ...)   // linia 51 — warn (zawsze logowane!)
```

Linia 51 jest na poziomie `warn` — logowana jest nawet przy `RUST_LOG=warn`. Username jest PII
(personally identifiable information). Logowanie go przy nieudanej rejestracji może tworzyć log
trail który narusza GDPR lub inne przepisy o prywatności.

**Do zrobienia**: Zastąp username w logach pseudonimem (np. skrót SHA-256) lub usuń pole
`handler` z logów warn/error. Zostaw tylko debug (który jest wyłączony w produkcji).

---

### H-6: JWT używa HS256 z kluczem który rotuje się razem z MK

**Plik**: `lithiums/src/transport/mod.rs`, `create_token_for_user`

JWT jest podpisywany kluczem `jwt_secret` derywowanym przez `HKDF(mk, b"lithium/jwt-secret/v1")`.
Przy rotacji MK (domyślnie co godzinę) `jwt_secret` zmienia się. Jeśli rotacja zdarzy się
podczas aktywnej sesji, wszystkie istniejące JWT stają się nieważne. Przy TTL JWT = 120 sekund
jest to mało prawdopodobne, ale możliwe.

Audytor zapyta dlaczego JWT secret jest zrotacyjny i czy jest to zamierzone zachowanie.

**Do zrobienia**: Udokumentuj tę właściwość. Rozważ użycie osobnego, stabilnego JWT secret
nie powiązanego z MK, lub zwiększ TTL JWT > `rotate_every`.

---

### H-7: Brak weryfikacji długości klucza ML-KEM w invite code decode

**Plik**: `lithiumd/src/commands/invite_codec.rs`, `decode_invite_code`

Przy dekodowaniu invite code, długość klucza Kyber (`k_pub`) i Dilithium (`dili_pub`) są
czytane z blob i akceptowane bez weryfikacji że pasują do oczekiwanych rozmiarów
(ML-KEM-1024 public key = 1568 bytes, ML-DSA-87 public key = 2592 bytes). Akceptowany jest
dowolny rozmiar.

Audytor zapyta: "co się stanie jeśli ktoś prześle klucz Kyber 512 zamiast 1024?"
Biblioteka `pqcrypto` prawdopodobnie zwróci błąd przy próbie użycia, ale błąd powinien
być wychwycony wcześniej z bardziej informatywnym komunikatem.

**Do zrobienia**: Dodaj walidację długości:
```rust
if k_pub.len() != 1568 { return Err(...); }   // ML-KEM-1024 pk
if dili_pub.len() != 2592 { return Err(...); } // ML-DSA-87 pk
```

---

### H-8: `/msg/fetch` nie wymaga JWT — wystarczą efemeryczne klucze

**Plik**: `lithiums/src/main.rs`, linia 70–75

```rust
CryptoCfg::session("msg_fetch").auth(AuthMode::KeysInHeaders)
```

Pobieranie wiadomości wymaga tylko `KeysInHeaders` (efemeryczne klucze + podpis), nie JWT.
Oznacza to że każdy kto zna adres mailboxa (32 bajty) może pobrać z niego wiadomości bez
logowania. Dostęp kontrolowany jest wyłącznie przez nieodgadywalność adresu mailboxa.

To może być zamierzone (anonimowy fetch), ale audytor będzie potrzebował wyjaśnienia.
Szczególnie: czy adres mailboxa jest wystarczającym sekretem? (Tak — 32 bajty z X25519 DH,
computationally hard to brute-force.)

**Do zrobienia**: Dodaj komentarz w kodzie wyjaśniający ten świadomy wybór projektowy.

---

---

### H-9: `ensure_kyber`/`ensure_dilithium` nadpisują klucz prywatny gdy brakuje pliku pub

**Plik**: `lithium_core/src/keys/manager.rs`, linie 203–234

To jest rzeczywisty **bug kryptograficzny**, nie tylko kwestia stylu. Gdy plik klucza
prywatnego istnieje ale plik klucza publicznego nie (np. po błędnym deploymencie), zamiast
odtworzyć klucz publiczny z zapisanego klucza prywatnego, kod generuje **zupełnie nową parę**
i nadpisuje klucz prywatny:

```rust
if priv_path.exists() {
    let _ = load_bytes_decrypted(&priv_path, mk, KT_KYBER)?;  // wczytuje i ignoruje
    if !pub_path.exists() {
        let (pk, sk) = mlkem1024::keypair();     // NOWA para kluczy!
        save_bytes_encrypted(&priv_path, ...)?;  // nadpisuje stary priv key!
    }
}
```

Kontrast z poprawną implementacją dla Ed25519/X25519 które prawidłowo odtwarzają klucz
publiczny z zapisanego klucza prywatnego.

**Konsekwencja**: Każde przypadkowe usunięcie pliku `.pub` (np. podczas restore backupu
który przywrócił tylko klucze prywatne) powoduje cichą rotację kluczy — bez błędu, bez
logowania, z sukcesem przy starcie. Wszyscy istniejący kontakty nie mogą już komunikować się
z tym demonem.

**Audytor zada pytanie**: "Jak może dojść do takiej sytuacji? Czy ten scenariusz był testowany?"
Brak testu dla tego przypadku (backup recovery) będzie red flag.

**Do zrobienia**:
1. Dla ML-KEM-1024 i ML-DSA-87: zapisz klucz publiczny wewnątrz zaszyfrowanego pliku klucza
   prywatnego lub trzymaj go w `.pub` i zaszyfruj razem z kluczem prywatnym
2. Alternatywnie: zwróć błąd gdy klucz prywatny istnieje a publiczny nie — nie generuj nowego
3. Dodaj test integracyjny: delete pub file → restart → verify priv key unchanged

---

### H-10: Nieatomowa rotacja MK w `maybe_rotate_mk` — crash = utrata kluczy

**Plik**: `lithium_core/src/keys/manager.rs`, linie 153–165

Rotacja MK (domyślnie co godzinę) przebiega przez 5 kroków sekwencyjnych. Jeśli proces
zostanie ubity między krokami 1–4 a krokiem 5 (zapis nowego MK na dysk), pliki kluczy
prywatnych są częściowo zaszyfrowane nowym MK, a na dysku wciąż jest stary MK. Przy kolejnym
starcie stary MK nie odszyfruje przepisanych plików.

**Konsekwencja**: Trwała utrata kluczy prywatnych — demon nie wystartuje.

**Audytor zada pytanie**: "Jak testujesz że rotacja kluczy jest bezpieczna pod kątem awarii
systemu?" Brak odpowiedzi lub brak testu = red flag.

**Do zrobienia**: Zaimplementuj dwufazowy commit:
1. Zapisz nowy MK do `mk.pending` (atomicznie przez `rename`)
2. Przepisz wszystkie keyfile'y
3. Rename `mk.pending` → `mk`
4. Przy starcie: jeśli istnieje `mk.pending`, dokończ lub cofnij rotację

---

## ŚREDNIE — warto naprawić

### M-1: Brak `SECURITY.md` i modelu zagrożeń

Zewnętrzny audytor prawie zawsze prosi o:
1. **Threat model** — kim jest atakujący, jakie ma możliwości, co chronimy
2. **Założenia bezpieczeństwa** — co musi być prawdą żeby system był bezpieczny
3. **Znane ograniczenia** — co celowo nie jest chronione

Bez tych dokumentów audytor musi sam domyślać się założeń, co wydłuża czas i koszt audytu.

**Do zrobienia**: Napisz `SECURITY.md` z:
- Modelem zagrożeń (MitM na poziomie sieci, malicious server, kompromitacja klucza)
- Właściwościami bezpieczeństwa (E2E szyfrowanie, forward secrecy przez ratchet, PQ security)
- Jawnie wylistowanymi założeniami (bezpieczny kanał OOB do wymiany invite, zaufany OS)
- Elementami poza scopem (bezpieczeństwo GUI, DoS resistance)

---

### M-2: Brak workspace-level Cargo.toml z ujednoliconymi wersjami zależności

Różne crate'y używają różnych wersji tych samych bibliotek:
- `argon2`: `0.6.0-rc.1` (core) vs `0.6.0-rc.7` (daemon)
- `sea-orm`: `2.0.0-rc.32` (core, daemon) vs `2.0.0-rc.36` (server)
- `tracing-subscriber`: `0.3.22` (daemon) vs `0.3.1` (server)

Audytor sprawdzi `Cargo.lock` i zobaczy że te wersje mogą się rzeczywiście różnić (lub nie —
semver pozwoli na to samo). Niespójności budzą pytania.

**Do zrobienia**: Użyj workspace-level dependencies w głównym `Cargo.toml`:
```toml
[workspace.dependencies]
argon2 = { version = "0.6", features = ["zeroize"] }
sea-orm = { version = "2.0", features = [...] }
```

---

### M-3: `AppError` ujawnia wewnętrzne kody błędów w odpowiedziach HTTP

**Plik**: `lithiums/src/error.rs`, linia 95–98

```rust
let body = json!({
    "ok": false,
    "error": self.msg,  // np. "invalid jwt 1", "invalid jwt 2", "invalid jwt 3"...
});
```

Kody błędów jak `"invalid jwt 1"`, `"invalid jwt 2"`, `"invalid jwt 3"` (z `transport/mod.rs`
linie 204, 209, 212, 220, 226) w odpowiedziach HTTP dają atakującemu informację o tym na
którym etapie weryfikacji JWT zawiodła. Ułatwia to enumerację i debugowanie ataków.

**Do zrobienia**: Zamień numerowane kody błędów na jeden generyczny `"invalid_token"` w
odpowiedziach HTTP. Szczegółowe kody zachowaj tylko w logach serwera (z odpowiednim poziomem
logowania).

---

### M-4: Brak limitu rozmiaru dla kluczy Kyber/Dilithium w invite code

**Plik**: `lithiumd/src/commands/invite_codec.rs`, `encode_invite_code` linia 41

```rust
if k_pub.len() > u16::MAX as usize || dili_pub.len() > u16::MAX as usize {
    return Err(LithiumError::internal());
}
```

Limit to `u16::MAX` = 65535 bajtów. Właściwe rozmiary to ~1568 (Kyber) i ~2592 (Dilithium).
Akceptowanie kluczy do 65KB jako "poprawnych" w invite codzie to potencjalny DoS vector —
ktoś może wygenerować invite code z 64KB "kluczem" co spowoduje niepotrzebne przetwarzanie.

**Do zrobienia**: Ogranicz do faktycznych rozmiarów algorytmu + margin (~10%).

---

### M-5: `pad_data` i `pad_headers` powielone identycznie na kliencie i serwerze

**Pliki**: `lithiumd/src/protocol_manager.rs` (linie 613–649) i `lithiums/src/transport/mod.rs` (linie 701–744)

Obie implementacje `pad_block`, `pad_data`, `pad_headers`, `unpad_block` są copy-paste
z drobnymi różnicami (np. `out.resize` vs `out.extend(iter::repeat)`). Jeśli pojawi się bug
w jednej wersji (np. off-by-one w unpad), może nie być w drugiej — protocol desync.

**Do zrobienia**: Przenieś padding do `lithium_core` jako jedyną implementację.

---

### M-6: Brak obsługi błędu `SystemTime` przed UNIX epoch w `now_hex_seconds`

**Plik**: `lithiumd/src/protocol_manager.rs`, linia 594

```rust
.duration_since(UNIX_EPOCH)
.unwrap_or_default()  // silently returns 0 on error!
```

Jeśli zegar systemowy jest przed 1 stycznia 1970 (np. misconfigured VM), timestamp = 0.
Serwer odrzuci żądanie jako "too old", ale klient będzie próbował w kółko nie wiedząc dlaczego.
Analogicznie w `transport/mod.rs` linia 694 (`get_now`) używa `map_err` — poprawnie zwraca błąd.

**Do zrobienia**: Zamień `unwrap_or_default()` na właściwe propagowanie błędu.

---

### M-7: `users_uuid_namespace` w `DataManager` ręcznie modyfikuje bajty UUID

**Plik**: `lithium_core/src/db/manager.rs`, linie 27–34

```rust
b[6] = (b[6] & 0x0f) | 0x50;  // Version 5
b[8] = (b[8] & 0x3f) | 0x80;  // Variant RFC4122
```

Namespace dla UUID-v5 jest generowany z HKDF i ręcznie zamieniane są bity wersji/variant.
To nie jest kryptograficznie problematyczne, ale jest nieeleganckie — wynikowe "UUID" jest
właściwie pseudolosową wartością z naniesionymi bitami zgodności UUID. Audytor zapyta
czy to jest zamierzone i dlaczego nie użyto standardowego generatora UUID-namespace.

**Do zrobienia**: Użyj z góry zdefiniowanego namespace UUID (może być taki sam dla wszystkich
instancji — to `Uuid::new_v5(ns, handler)` zapewnia determinizm, a ns jest de facto
secretem via HKDF), lub udokumentuj dlaczego dynamiczny namespace jest potrzebny.

---

### M-8: Timestamp w żądaniu nie jest chroniony przed manipulacją na poziomie AAD

**Plik**: `lithiumd/src/protocol_manager.rs`, linia 370

```rust
obj_mut(&mut body)?.insert("timestamp".into(), Value::String(now_hex_seconds()));
```

Timestamp jest wstrzykiwany do body JSON przed podpisaniem i szyfrowaniem. Jest więc
objęty podpisem klienta (Ed25519 + ML-DSA). Weryfikacja timestamp na serwerze dzieje się
po weryfikacji podpisu, więc jest poprawnie wiązana z żądaniem. Ale audytor sprawdzi
czy timestamp jest weryfikowany w ramach zaszyfrowanego body (tak jest — w `body_json.get_string("timestamp")`
po dekryptacji), co jest poprawne.

Brak problemu, ale warto to udokumentować jako świadoma decyzja projektowa.

---

## NISKIE — estetyka i styl kodu

### L-1: Użycie `log::info!` i `tracing::...` jednocześnie

**Plik**: `lithiums/src/main.rs`, linia 17 i 130

```rust
use log::info;  // linia 17 (nieużywane — generuje warning)
...
.with(Tracing)  // linia 130 — poem Tracing middleware
```

`log::info` jest importowany ale nieużywany (zakomentowany kod poniżej). Codebase
miesza `log` crate (dla `info!`) i `tracing` crate (dla `debug!`, `error!`, `warn!`).
To nie jest security issue ale wygląda nieporządnie.

**Do zrobienia**: Usuń `use log::info;`, używaj wyłącznie `tracing`.

---

### L-2: Magia numeryczna zamiast stałych dla rozmiarów kluczy PQ

W wielu miejscach hardcoded rozmiary jak `1..13` (nonce), `1568`, `2592` nie są stałymi.
Lepiej byłoby:
```rust
const MLKEM1024_PK_LEN: usize = 1568;
const MLDSA87_PK_LEN: usize = 2592;
```

---

### L-3: `#[allow(dead_code)]` na polach struct w `db/repo.rs`

**Plik**: `lithiumd/src/db/repo.rs`, linie 18–26 (`ContactRow`), 30–38 (`MessageRow`)

```rust
#[allow(dead_code)]
pub struct ContactRow {
    pub contact_id: Vec<u8>,
    ...
```

`#[allow(dead_code)]` oznacza że pola są definiowane ale nie używane. To może wskazywać
na nieukończoną implementację lub martwy kod. Audytor zapyta co jest planowane.

**Do zrobienia**: Albo usuń nieużywane pola, albo faktycznie użyj ich (np. w
`contact_list.rs`), albo udokumentuj że to MVP-stub.

---

### L-4: Brak `.gitignore` dla danych runtime (sqlite, klucze)

Prawdopodobnie katalogi `./data/`, `./share/` z kluczami i bazą danych mogą
przypadkowo trafić do commita.

**Do zrobienia**: Dodaj do `.gitignore`:
```
data/
share/
*.db
*.keyf
*.sock
.env
```

---

## Podsumowanie priorytetów

| ID  | Priorytet | Opis |
|-----|-----------|------|
| B-1 | Blokujące | `.env` z hasłami i kluczami w repo — usuń i obróć klucze |
| B-2 | Blokujące | `RUST_LOG=debug` w produkcji — loguje wrażliwe dane |
| B-3 | Blokujące | Brak jakichkolwiek testów jednostkowych |
| B-4 | Blokujące | Pre-release/RC wersje bibliotek kryptograficznych |
| B-5 | Blokujące | Brak jawnych feature flag `zeroize` na crypto deps |
| H-1 | Wysokie   | Zakomentowany debug kod w `main.rs` |
| H-2 | Wysokie   | Brak dokumentacji wymogu TLS proxy |
| H-3 | Wysokie   | Wiadomości tracone po restarcie — niezadokumentowane |
| H-4 | Wysokie   | Nieużywane crypto dependencies w Cargo.toml |
| H-5 | Wysokie   | Username logowany na poziomie warn (zawsze aktywnym) |
| H-6 | Wysokie   | JWT secret rotuje się z MK — może invalidować sesje |
| H-7 | Wysokie   | Brak walidacji długości kluczy PQ w invite codec |
| H-8 | Wysokie   | `/msg/fetch` bez JWT — wymaga wyjaśnienia w dokumentacji |
| M-1 | Średnie   | Brak SECURITY.md i threat model |
| M-2 | Średnie   | Niespójne wersje deps między crateami |
| M-3 | Średnie   | Numerowane kody błędów JWT w HTTP response |
| M-4 | Średnie   | Brak górnego limitu rozmiaru kluczy PQ w invite |
| M-5 | Średnie   | Padding zduplikowany client/server zamiast w core |
| M-6 | Średnie   | `unwrap_or_default()` na SystemTime — cichy błąd |
| M-7 | Średnie   | UUID namespace manualnie modyfikowany — niejasna intencja |
| L-1 | Niskie    | Mieszanie `log` i `tracing` crate |
| L-2 | Niskie    | Magia numeryczna zamiast stałych dla rozmiarów kluczy PQ |
| L-3 | Niskie    | `#[allow(dead_code)]` na polach struct — martwy kod |
| L-4 | Niskie    | Brak odpowiedniego `.gitignore` dla runtime danych |