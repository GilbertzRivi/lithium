# Audyt bezpieczeństwa: `lithiumd`

Data: 2026-03-12
Audytor: Claude Code (claude-sonnet-4-6)
Zakres: crate `lithiumd` — daemon IPC, zarządzanie stanem, kryptografia E2E, mailbox, baza danych
Klasyfikacja zgodna z `lithium_assumptions.md`: Podatność / Trade-off / Non-goal / Obserwacja

---

## Podsumowanie wykonawcze

`lithiumd` to daemon odpowiedzialny za całą lokalną logikę: odblokowywanie keystoru, zarządzanie kontaktami, szyfrowanie E2E, komunikację z serwerem i lokalny IPC. Ogólna jakość implementacji jest wysoka — poprawne użycie `SecretJson`/`zeroize`, domenowo-separowane AAD, dwupodpisowe E2E z pełnym kontekstem, padding blokowy, crash-consistent rotacja kluczy.

Zidentyfikowano **cztery podatności właściwe** dotyczące granicy IPC (którą `lithium_assumptions.md` explicite klasyfikuje jako krytyczną), **trzy trade-offy** operacyjne i kilka obserwacji. Oryginalny T-04 (kolejność DB/serwer) był oparty na błędnym odczytaniu kodu — faktyczna kolejność jest odwrotna (serwer najpierw, DB potem) i jest poprawna.

---

## PODATNOŚCI

### P-01 — Porównanie tokenu sesji IPC nie jest constant-time

**Plik:** `lithiumd/src/ipc/mod.rs:73`
**Klasyfikacja:** Podatność — Średni

```rust
if provided.as_bytes() != expected.as_bytes() {
    return Some(err_resp(req.id, "ipc_auth_failed"));
}
```

Token sesji IPC (64-znakowy hex, 256-bit entropii) porównywany operatorem `!=` na `&[u8]`. Rust nie gwarantuje constant-time — może generować early-exit przy pierwszym różnym bajcie.

**Dlaczego jest to podatność:** `lithium_assumptions.md` explicite klasyfikuje IPC jako krytyczną granicę bezpieczeństwa:
> *„dlatego problemy dotyczące IPC, lokalnej autoryzacji, uprawnień i modelu stanu są realnymi problemami bezpieczeństwa"*

Token sesji jest głównym mechanizmem autoryzacji wszystkich uprzywilejowanych poleceń po odblokowaniu. Jego kompromitacja daje pełny dostęp do odblokowanego daemona.

**Mitigacje zmniejszające ryzyko:** Na Linuxie `SO_PEERCRED` wiąże token z UID/PID (linia 79–89). Timing oracle wymaga dostępu do socketu (zależność od uprawnień grupy).

**Rekomendacja:**
```rust
use subtle::ConstantTimeEq;
if provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
```

---

### P-02 — Hasła i treść wiadomości deserializowane jako `String` przez IPC

**Plik:** `lithiumd/src/ipc/types.rs:19–32`
**Klasyfikacja:** Podatność — Niski

```rust
UnlockKeystore { data_password: String },
SetCredentials { handler: String, password: String },
ContactSend { contact_id: String, plaintext: String },
```

Trzy miejsca wrażliwych danych przechodzą przez typ `String` (bez `Zeroize`) przed konwersją do `SecretString`. `serde_json` tworzy pośrednie alokacje `String` podczas parsowania JSON. Te alokacje pozostają w pamięci do momentu nadpisania przez alokator — bez gwarancji.

**Dlaczego jest to podatność:** `lithium_assumptions.md` wprost wymienia zagrożenie:
> *„pamięć operacyjna może zostać przejęta lub zdumpowana"*

Okno ekspozycji jest krótkie (natychmiastowe `SecretString::new_checked(data_password)` itp.), ale alokacje pośrednie przez `serde_json` nie są kontrolowane.

**Szczególnie istotne:** `plaintext: String` w `ContactSend` — treść wiadomości, nie tylko hasło.

**Rekomendacja:** Custom `Deserialize` dla `SecretString` / opakowanie z natychmiastowym zeroize bufora pośredniego. Alternatywnie: odbiór przez osobny kanał (e.g., `secrecy::Secret<String>`).

---

### P-03 — Non-CT porównanie hasła w `already_unlocked`

**Plik:** `lithiumd/src/commands/unlock_keystore.rs:40`
**Klasyfikacja:** Podatność — Niski

```rust
Some(cur) if cur.expose() == dp.expose() => IpcResponse { ok: true, ... },
_ => err_resp(id, "bad_data_password"),
```

Gdy daemon jest już odblokowany, podane hasło porównywane jest z aktualnym hasłem unlock za pomocą zwykłego `==` na `&str` (nie constant-time).

**Dlaczego jest to podatność:** `UnlockKeystore` nie wymaga auth tokenu (`cmd_requires_auth` wyklucza je z wymogów):
```rust
fn cmd_requires_auth(cmd: &IpcCommand) -> bool {
    !matches!(cmd, IpcCommand::Ping | IpcCommand::UnlockKeystore { .. })
}
```
Każdy proces mający dostęp do socketu IPC (domyślnie: ta sama grupa, socket 0o660) może wywołać `UnlockKeystore` z dowolnym hasłem i zmierzyć czas odpowiedzi. Timing oracle ujawnia ile bajtów podanego hasła zgadza się z aktualnym hasłem unlock.

**Rekomendacja:**
```rust
use subtle::ConstantTimeEq;
let same = cur.as_bytes().ct_eq(dp.expose().as_bytes()).unwrap_u8() == 1;
```

---

### P-04 — Statyczna sól w `derive_password_root` — brak per-instalacja entropii

**Plik:** `lithiumd/src/password_provider.rs:17, 56–58`
**Klasyfikacja:** Podatność — Niski

```rust
const USER_ROOT_SALT: &[u8] = b"lithium/user-provider/root/v1";

fn derive_password_root(&self) -> Result<Byte32> {
    self.argon2_32(USER_ROOT_SALT)  // ta sama sól dla każdego użytkownika
}
```

`derive_password_root` używana jest tylko przez `derive_combined_root`, który buduje klucz pochodny wg:
```
combined_root = HKDF(server_dek, salt=Argon2id(password, STATIC_SALT), label)
```

**Co to oznacza w praktyce:** Argon2id z identycznym hasłem i identyczną statyczną solą zawsze produkuje ten sam `pass_root`. Atakujący z dostępem do dwóch plików keystoru (dwóch użytkowników lub dwóch instalacji) i tymi samymi hasłami może potwierdzić identyczność hasła, bo `pass_root` będzie taki sam. Przy ataku słownikowym: jedno obliczenie Argon2id pozwala testować hasło jednocześnie przeciwko wszystkim użytkownikom (zamiast osobno dla każdego).

**Ważne mitigacje:**
1. Plik keystoru (MK) szyfrowany jest przez `derive_user_key(salt)` z LOSOWĄ solą (32 bajty) wbudowaną w plik — ten mechanizm jest poprawny
2. `derive_combined_root` używa `server_dek` jako wejścia klucza — zapewnia per-użytkownik entropię w finalnym kluczu
3. Statyczna sól działa TYLKO jako salt dla `derive_password_root`, nie dla MK

Podatność zmniejsza efektywność Argon2id przy wieloużytkownikowych atakach słownikowych, ale nie pozwala bezpośrednio odtworzyć klucza bez znajomości `server_dek`.

**Rekomendacja:** Dodać per-instalacja losową sól (np. 32 bajty przechowywane jawnie obok pliku MK) i przekazywać ją do `derive_password_root` zamiast stałej.

---

## TRADE-OFFY

### T-01 — Socket IPC z uprawnieniami grupy (0o660)

**Plik:** `lithiumd/src/ipc/unix.rs:51`
**Klasyfikacja:** Trade-off — Operacyjny

```rust
let old_umask = unsafe { libc::umask(0o117) };  // wynikowe uprawnienia: 0o660
```

Socket dostępny dla wszystkich procesów w tej samej grupie. Domyślnie `LITHIUMD_IPC_ALLOWED_UID` nie jest ustawione (`None`), więc `authorize_peer` nie filtruje po UID na poziomie accept — tylko token sesji + SO_PEERCRED binding chronią po stronie protokołu.

**Mitigacje:** `SO_PEERCRED` wiąże token sesji z UID/PID. `LITHIUMD_IPC_ALLOWED_UID` env var pozwala ograniczyć dostęp na poziomie accept. Opcja `0o600` byłaby bezpieczniejsza.

**Rekomendacja:** Rozważyć domyślne `umask(0o177)` (0o600) jeśli cross-group IPC nie jest wymagane. Udokumentować `LITHIUMD_IPC_ALLOWED_UID` jako zalecany hardening.

---

### T-02 — Fallback ścieżki socketu do katalogu tymczasowego

**Plik:** `lithiumd/src/util.rs:63–68`
**Klasyfikacja:** Trade-off — Niski

```rust
IpcEndpoint::Unix(std::env::temp_dir().join(sock_name))  // /tmp/lithiumd-USER.sock
```

Gdy `XDG_RUNTIME_DIR` i `LITHIUMD_SOCKET_PATH` są nieustawione, socket ląduje w `/tmp/` — katalogu widocznym dla wszystkich użytkowników systemu.

**Mitigacje w kodzie:** `bind_private_listener` sprawdza istniejący plik przed bind — jeśli nie jest socketem, daemon odmawia startu (ochrona przed symlink-race). Dotyczy tylko niestandardowych środowisk bez `XDG_RUNTIME_DIR`.

**Rekomendacja:** Logować ostrzeżenie przy użyciu fallbacku. Standardowe systemy (systemd, GNOME) zawsze ustawiają `XDG_RUNTIME_DIR` z uprawnieniami `0o700`.

---

### T-03 — Brak rate limiting na `UnlockKeystore`

**Plik:** `lithiumd/src/commands/unlock_keystore.rs`
**Klasyfikacja:** Trade-off — Niski

`UnlockKeystore` nie limituje liczby prób w jednostce czasu. Argon2id (64MB, 3 iteracje) kosztuje ~200ms/próbę — stanowi naturalne ograniczenie (~300 prób/min przy 1 wątku).

**Uzasadnienie projektowe:** Atak wymaga lokalnego dostępu do socketu IPC. Argon2id zapewnia podstawowe ograniczenie tempa. Dokładna ochrona środowiska lokalnego jest poza zakresem Lithium (`lithium_assumptions.md`: *„lokalne środowisko klienta nie jest domyślnie bezpieczne"*).

**Rekomendacja:** Proste zabezpieczenie: licznik prób w `DaemonState` z blokadą czasową po N nieudanych próbach (np. 5 prób → 30s blokada).

---

## NON-GOALS (nie raportowane jako błędy)

Zgodnie z `lithium_assumptions.md`, poniższe właściwości są celowymi decyzjami projektowymi:

| Właściwość | Podstawa w założeniach |
|------------|------------------------|
| Brak gwarancji dostarczenia wiadomości | *„Lithium nie gwarantuje dostarczenia każdej wiadomości"* |
| Utrata lokalnych danych przy utracie urządzenia/klucza | *„recoverability przegrywa z bezpieczeństwem"* |
| Brak offline unlock bez `server_dek` | *„Brak pełnego offline unlock"* |
| Serwer wysyłany przed DB (kolejność w `contact_send`) | Priorytet dostarczenia > lokalny zapis; w modelu bez gwarancji |

### Korekta T-04 z poprzedniego audytu

Poprzedni audyt twierdził: *„lokalny stan DB aktualizowany przed potwierdzeniem dostarczenia do serwera"*. To było błędne.

Faktyczna kolejność w `contact_send.rs`:
```
1. proto.send(MsgSend, ...) → serwer PIERWSZA operacja
2. Jeśli błąd → early return (DB nie ruszana)
3. dm.upsert_contact(...) → aktualizacja stanu kontaktu w DB
4. dm.add_message(...) → lokalny zapis wiadomości
```

Serwer jest zawsze aktualizowany jako pierwszy. Przy awarii po wysłaniu do serwera (przed zapisem do DB): wiadomość dotarła do odbiorcy, ale nadawca nie ma lokalnego śladu — to jest dopuszczalne w modelu bez gwarancji dostarczenia.

---

## OBSERWACJE

### O-01 — Weryfikacja podpisów E2E sekwencyjna (nie równoległa)

**Plik:** `lithiumd/src/commands/e2e.rs:426–434`

```rust
if !sign::verify_signature(sig_input.as_slice(), sig_ed.as_slice(), &ed_pub) {
    return Err(malicious_message_err());  // ML-DSA-87 nie sprawdzana przy błędzie Ed25519
}
if !sign::verify_signature_dili(sig_input.as_slice(), sig_dili.as_slice(), &dili_pub) {
    return Err(malicious_message_err());
}
```

Inaczej niż po stronie serwera (gdzie obie weryfikacje są zawsze obliczane), tutaj weryfikacja Ed25519 short-circuituje ML-DSA-87. Daje to teoretyczny timing oracle dla złośliwego peera (mógłby odróżnić "Ed25519 ok, ML-DSA-87 błędny" od "Ed25519 błędny"). Praktyczne ryzyko jest minimalne — atakujący zna własne klucze i wie, czy ich sygnatura jest prawidłowa.

---

### O-02 — `contact_fetch` zapisuje stan kontaktu PRZED pobraniem z serwera

**Plik:** `lithiumd/src/commands/contact_fetch.rs:113–144, 368–397`

Mailbox state jest zapisywany do DB na początku `contact_fetch` (przed wysłaniem do serwera), a następnie ponownie po zakończeniu wszystkich deszyfracji. Dzięki temu, jeśli fetch częściowo zawiedzie, zaktualizowany stan skrzynki jest już bezpiecznie zapisany. Dobra praktyka crash-consistency.

---

### O-03 — Atomowe jednorazowe zużycie prekey z `take`

**Plik:** `lithiumd/src/commands/contact_fetch.rs:265`

```rust
let prekey_blob = match dm.take_prekey(&w.to_id).await { ... };
```

`take_prekey` usuwa prekey atomowo przy pobraniu. Eliminuje race condition przy podwójnym użyciu tego samego prekey z równoległych operacji.

---

### O-04 — Wycofanie bootstrap kluczy prywatnych po ustanowieniu sesji

**Plik:** `lithiumd/src/commands/e2e.rs:197–238` — `maybe_drop_bootstrap_private`

Po pierwszym pomyślnym odebraniu wiadomości przez normalny ratchet (`ack_seq > 0`), klucze prywatne bootstrap (`x_priv`, `k_priv`) są usuwane z `self_state`. Minimalizacja retencji kluczy po ich użyciu.

---

### O-05 — Per-kontaktowy mutex na `contact_fetch`

**Plik:** `lithiumd/src/commands/contact_fetch.rs:80–81`

```rust
let contact_lock = state.contact_fetch_lock(contact_id.as_slice()).await;
let _contact_guard = contact_lock.lock().await;
```

Równoległe fetche dla tego samego kontaktu serializowane przez per-kontaktowy mutex. Zapobiega duplikacji wiadomości i wyścigowi na aktualizacji stanu skrzynki.

---

### O-06 — Podpis E2E obejmuje pełny kontekst

**Plik:** `lithiumd/src/commands/e2e.rs:291–311` — `build_sig_input`

```
sig_input = E2E_SIG_LABEL || to_id || from_x_pub || len32(hdr_unsigned) || hdr_unsigned || len32(pt_body) || pt_body
```

Podpis wiąże: nadawcę (przez klucz prywatny), odbiorcę (`to_id`), efemeryczny klucz nadawcy (`from_x_pub`), nagłówek (tryb, seq, mailbox, prekeys) i ciało. Uniemożliwia replay i cross-user replay.

---

### O-07 — Efemeryczne klucze podpisu dla Shake i MsgFetch

**Plik:** `lithiumd/src/protocol_manager.rs:364–370` — `sign_dual_ephemeral`

`/shake` i `/msg/fetch` podpisywane są świeżymi kluczami efemerycznymi (nie długoterminowymi kluczami tożsamości). Serwer nie może powiązać tych żądań z konkretną tożsamością użytkownika. Świadoma decyzja projektowa dla prywatności.

---

### O-08 — `lock_keystore()` zeruje cały wrażliwy stan atomicznie

**Plik:** `lithiumd/src/state.rs:82–103`

```rust
*self.dek_plain.lock().await = None;    // DEK (SecretBytes → zeroize na drop)
*self.data_pass.lock().await = None;   // hasło (SecretString → zeroize)
*self.account_creds.lock().await = None; // handler+pass serwera
*self.proto.lock().await = None;       // ProtocolManager (klucze sesji)
*self.local_db.lock().await = None;
*self.keys.lock().await = None;
ipc.session_token = None;             // token IPC
```

Przy lock, zarówno jawnym jak i przy awarii, wszystkie wrażliwe elementy stanu usuwane są przez `Option::take()`, triggerując `zeroize` przez `Drop` dla typów `SecretString`/`SecretBytes`/`Byte32`.

---

## MOCNE STRONY

**S-01 — Dwuczynnikowy klucz główny: hasło + server_dek**
`combined_root = HKDF(server_dek, salt=Argon2id(password, salt))` — kompromitacja hasła bez `server_dek` lub `server_dek` bez hasła nie pozwala odtworzyć klucza głównego lokalnej bazy.

**S-02 — Crash-consistent rotacja MK** — protokół `staged → ready → commit` z fsync. Bezpieczny restart po awarii w dowolnym punkcie.

**S-03 — `SO_PEERCRED` jako warunek konieczny autoryzacji na Linuxie** — token sesji wiązany z UID/PID klienta. Nawet ujawniony token nie pozwala na użycie przez inny proces.

**S-04 — Domenowo-separowane AAD dla wszystkich blobów bazy** (`contact-self/v1`, `contact-peer/v1`, `message/v1`, `prekey/v1`) — cross-type replay niemożliwy.

**S-05 — Padding blokowy 32KB–64KB** dla żądań do serwera — ukrycie rozmiaru wiadomości.

**S-06 — Rotacja kluczy outbound mailbox** (co `DEFAULT_WINDOW=32` wiadomości) — kompromitacja jednego klucza outbound ogranicza do ≤32 wiadomości historii.

**S-07 — Prekey jako mechanizm recovery** — atomowo zabezpieczony przed podwójnym użyciem, obsługuje scenariusz utraty urządzenia przez peera.

---

## Podsumowanie ustaleń

| ID   | Opis                                                          | Klasyfikacja | Priorytet |
|------|---------------------------------------------------------------|--------------|-----------|
| P-01 | Non-CT porównanie tokenu sesji IPC                            | Podatność    | Średni    |
| P-02 | Hasła i plaintext jako `String` w IPC — brak zeroize         | Podatność    | Niski     |
| P-03 | Non-CT porównanie hasła przy already_unlocked                 | Podatność    | Niski     |
| P-04 | Statyczna sól Argon2 w derive_password_root                   | Podatność    | Niski     |
| T-01 | Socket IPC 0o660 — dostęp grupowy                            | Trade-off    | Operacyjny|
| T-02 | Fallback socketu do /tmp przy braku XDG_RUNTIME_DIR          | Trade-off    | Niski     |
| T-03 | Brak rate limiting na UnlockKeystore                          | Trade-off    | Niski     |

## Rekomendowany priorytet napraw

1. **P-01** — 1 linia: `subtle::ConstantTimeEq`, krytyczna granica IPC
2. **P-03** — 1 linia: `subtle::ConstantTimeEq`, eliminuje timing oracle na unlock
3. **P-04** — dodanie per-instalacja losowej soli do keystoru (wymaga migracji)
4. **P-02** — custom `Deserialize` dla `SecretString`/`SecretBytes` w `IpcCommand` (wymaga więcej pracy)
5. **T-01** — rozważyć domyślne `0o600`; udokumentować `LITHIUMD_IPC_ALLOWED_UID`
6. **T-03** — prosty licznik prób w `DaemonState`

---

*Audyt oparty na analizie statycznej kodu źródłowego (`lithiumd/src/`). Nie przeprowadzano testów dynamicznych. Patrz `lithium_core_audit.md` i `lithiums_audit.md` dla audytów pozostałych warstw.*