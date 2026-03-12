# Audyt bezpieczeństwa: `lithiums`

Data: 2026-03-12
Audytor: Claude Code (claude-sonnet-4-6)
Zakres: crate `lithiums` — serwer HTTP, warstwy pośrednie, kryptografia transportowa, API, baza danych
Klasyfikacja zgodna z `lithium_assumptions.md`: Podatność / Trade-off / Non-goal / Obserwacja

---

## Podsumowanie wykonawcze

Po uwzględnieniu `lithium_assumptions.md` zidentyfikowano **jedną właściwą podatność** (błąd implementacji kryptograficznej), **cztery trade-offy** operacyjne i kilka obserwacji. Zdecydowana większość pozycji z wcześniejszych wersji tego audytu to albo non-goals projektu, albo świadome decyzje projektowe wprost opisane w założeniach.

Najważniejsza korekta: w projekcie nie ma Redisa. `EphemeralStoreManager` z `lithium_core` to in-process `HashMap` + `BinaryHeap` TTL — czysty Rust, bez zewnętrznych zależności. Utrata stanu przy restarcie jest cechą, nie błędem.

---

## PODATNOŚCI

### P-01 — Porównanie JWT `sub` nie jest constant-time

**Plik:** `lithiums/src/transport/mod.rs:395`
**Klasyfikacja:** Podatność — Niski/Średni

```rust
if hmac_id(id, seed)? != sub {
    return Err(AppError::unauthorized("invalid jwt"));
}
```

`hmac_id` zwraca `String` (hex HMAC-SHA256). Porównanie `!=` na `String` nie jest constant-time — może zakończyć się przy pierwszym różnym bajcie, dając timing oracle.

**Kontekst ograniczający ryzyko:** Sprawdzenie jest redundantne względem dwóch wcześniejszych warstw weryfikacji:
1. Podpis JWT (HS256) — musi być ważny zanim `store.take` zostanie wywołany
2. `store.take` — seed istnieje tylko jeśli token był legalnie wystawiony; po `take` jest skonsumowany

Timing oracle ma sens tylko dla atakującego z ważnym tokenem JWT, co drastycznie ogranicza wektor. Niemniej zasada constant-time powinna być przestrzegana.

**Rekomendacja:**
```rust
use subtle::ConstantTimeEq;
if hmac_id(id, seed)?.as_bytes().ct_eq(sub.as_bytes()).unwrap_u8() == 0 {
    return Err(AppError::unauthorized("invalid jwt"));
}
```

---

## TRADE-OFFY

### T-01 — EphemeralStore in-process — restart zeruje anti-replay i rate-limit

**Pliki:** `lithium_core/src/utils/store.rs`, `lithiums/src/middleware/guard.rs`
**Klasyfikacja:** Trade-off — operacyjny

`EphemeralStoreManager` to in-process HashMap. Restart procesu kasuje:
- **Anti-replay cache** (TTL 600s) — window replay attack po restarcie w ciągu 60s od przechwycenia żądania
- **Rate-limit logowania i rejestracji** — liczniki per-handler zerowane
- **JWT tokeny i klucze sesji** — aktywne sesje unieważniane

**Dlaczego nie jest to Podatność w modelu Lithium:**
- Serwer jest z definicji niezaufany. Rate limiting i anti-replay to defense-in-depth, nie fundamentalna gwarancja.
- Rzeczywista ochrona przed brute-force hasła to wymóg podpisu kluczem prywatnym użytkownika (transport layer) przed jakąkolwiek weryfikacją hasła. Bez znajomości klucza prywatnego nie można nawet zainicjować próby logowania.
- Rzeczywista ochrona przed replay to konsumpcja kluczy sesji przez `store.take` — replayed request sesji i tak nie przejdzie bo klucz ses-x/ses-k jest już skonsumowany.

**Uzasadnienie projektowe:** EphemeralStore bez zewnętrznych zależności to świadomy wybór MVP. Dodanie Redisa/Valkey wprowadzałoby zależność infrastrukturalną.

**Rekomendacja:** Dokumentacja operacyjna: przy rolling deploys zachowaj okno (60s) przed przekierowaniem ruchu do nowego procesu, eliminując replay window po restarcie.

---

### T-02 — Klucze wiadomości efemeryczne w pamięci — utrata przy restarcie

**Plik:** `lithiums/src/db/repo.rs:359–371`
**Klasyfikacja:** Trade-off / Non-goal (utrata danych przy utracie komponentu)

```rust
// add_message: klucz w EphemeralStore (in-memory), szyfrogram w PostgreSQL
store.set(&id.to_string(), &SecretBytes::from_slice(msg_key.as_slice()), MSG_KEY_TTL).await?;
```

Restart serwera kasuje wszystkie klucze wiadomości. Szyfrogramy w PostgreSQL stają się nieodszyfrowane.

**Dlaczego nie jest to Podatność w modelu Lithium:**
Wprost opisane w `lithium_assumptions.md`:
- *„Lithium nie gwarantuje dostarczenia każdej wiadomości"* — non-goal
- *„możliwość utraty danych po utracie komponentu serwerowego"* — akceptowane założenie
- *„utrata części stanu mogła skutkować utratą danych, jeżeli zmniejsza to ryzyko kompromitacji"* — celowa asymetria

Klucze efemeryczne w pamięci (nie na dysku) gwarantują, że przejęcie PostgreSQL bez dostępu do live procesu nie ujawni treści wiadomości. To jest dokładnie zamierzony efekt.

**Rekomendacja operacyjna:** Poinformować użytkowników o krótkim oknie dostarczenia i potrzebie regularnego `fetch` przed planowanymi restartami serwera.

---

### T-03 — Serwer korzysta z `PlainFileMkProvider` — MK na dysku bez hasła

**Plik:** `lithiums/src/main.rs:40`
**Klasyfikacja:** Trade-off — Wysoki kontekstowo

Master Key serwera jako surowe bajty w pliku. Kompromitacja systemu plików = dostęp do MK = przez KEK→DEK — do zaszyfrowanych pól w PostgreSQL.

**Uzasadnienie:** Serwer nie ma użytkownika do wpisania hasła przy starcie. Alternatywy (HSM, Vault, systemd-creds) poza zakresem MVP.

**Rekomendacja:** Uprawnienia 0700 na `LITHIUM_KEYS_DIR`, szyfrowanie dysku, monitoring dostępu do pliku MK.

---

### T-04 — Brak TLS w warstwie transportowej

**Plik:** `lithiums/src/main.rs:58`
**Klasyfikacja:** Trade-off — Kontekstowy

Serwer nasłuchuje na czystym TCP. Poufność treści zapewniona przez KyberBox + AEAD. Atakujący MitM:
- Nie może czytać ani modyfikować treści
- Widzi metadane: IP, timing, rozmiar żądań (padding ogranicza)

**Uzasadnienie:** Oczekiwany TLS termination na reverse proxy (nginx/caddy). Aplikacyjna kryptografia zapewnia poufność nawet bez TLS.

---

## NON-GOALS (nie raportowane jako błędy)

Zgodnie z `lithium_assumptions.md` poniższe właściwości są celowymi decyzjami projektowymi i nie powinny być klasyfikowane jako podatności:

| Właściwość | Podstawa w założeniach |
|------------|------------------------|
| Brak gwarancji dostarczenia wiadomości | *„Lithium nie gwarantuje dostarczenia każdej wiadomości"* |
| Utrata wiadomości po restarcie serwera | *„możliwość utraty danych po utracie komponentu serwerowego"* |
| One-time fetch — wiadomość usuwana po pobraniu | *„Wiadomości projektowane jako one-time fetch"* |
| `/msg/fetch` dostępny przez KeysInHeaders (nie JWT) | Minimalizacja wiedzy serwera; mailbox jako tajny identyfikator; model ograniczonego zaufania |
| Brak skalowania poziomego (single-process store) | MVP, prostota, brak zewnętrznych zależności |
| Deterministyczne szyfrowanie ID użytkownika | Dokumentowane w kodzie; konieczne dla indeksowanego lookup |

---

## OBSERWACJE

### O-01 — Weryfikacja obu podpisów bez short-circuit

**Plik:** `lithiums/src/transport/mod.rs:776–789`

```rust
let ok_ed = sign::verify_signature(...);
let ok_dili = sign::verify_signature_dili(...);
if !(ok_ed && ok_dili) { ... }
```

Obie weryfikacje zawsze obliczane — brak timing oracle przez short-circuit. Dobra praktyka.

---

### O-02 — Anti-replay na ciphertexcie, przed odszyfrowaniem

**Plik:** `lithiums/src/middleware/guard.rs:125–143`

```rust
let key = format!("replay:{}", hex::encode(Sha256::digest(body)));
state.store.set_if_absent(&key, ..., Duration::from_secs(600)).await
```

Hash na zaszyfrowanym ciele przed kosztownym KyberBox decryption — replay odrzucany bez pełnego przetwarzania. TTL 600s = 10× okno timestamp (60s).

---

### O-03 — JWT jednorazowego użycia (`store.take`)

**Plik:** `lithiums/src/transport/mod.rs:383`

Replay tokenu niemożliwy niezależnie od podpisu i czasu ważności — token atomowo usuwany ze sklepu przy pierwszym użyciu.

---

### O-04 — `FOR UPDATE SKIP LOCKED` w `get_messages`

**Plik:** `lithiums/src/db/repo.rs:391`

Zapobiega podwójnemu dostarczeniu przy współbieżnych `fetch` dla tego samego mailboxa.

---

### O-05 — AAD wiadomości zawiera adres mailbox

**Plik:** `lithiums/src/db/repo.rs:341–346`

Cross-mailbox replay niemożliwy — wiadomość zaszyfrowana z `AAD = b"message-content/v1" || mailbox`.

---

### O-06 — `zeroize` na usuwaniu wpisów z EphemeralStore

**Plik:** `lithium_core/src/utils/store.rs:128–130, 74–76`

Klucze wiadomości i tokeny nadpisywane zerami przy usunięciu i wygaśnięciu TTL.

---

### O-07 — Rate limiting logowania per-handler, nie per-IP

**Plik:** `lithiums/src/transport/mod.rs:106–117`

Uniemożliwia blokowanie kont przez atakującego z innego IP. `GuardMiddleware` zapewnia globalny limit per-IP.

---

### O-08 — Padding 32–64KB na żądaniach i odpowiedziach

Losowy rozmiar bloku ukrywa rzeczywistą długość treści.

---

### O-09 — Handler przechowywany jako PHC hash, ale nigdy weryfikowany

**Plik:** `lithiums/src/db/repo.rs:223–224`

Argon2id PHC handlera zapisywany przy rejestracji, ale lookup realizowany przez UUID5. Zbędne ~200ms przy rejestracji. Nie jest błędem bezpieczeństwa — może służyć przyszłej weryfikacji.

---

## Mocne strony

**S-01 — Pełna aplikacyjna kryptografia E2E** — KyberBox (X25519 + ML-KEM-1024) + dual-signature (Ed25519 + ML-DSA-87) na każdym żądaniu. Kompromitacja serwera nie ujawnia treści wiadomości E2E.

**S-02 — JWT sub = HMAC(user_id, seed)** — Token nie zawiera user_id bezpośrednio. Trójwarstwowe zabezpieczenie: JWT-podpis + store-seed + HMAC.

**S-03 — Trzy niezależne warstwy rate limiting** — pre-IP flood guard, per-handler login backoff, per-handler register lock.

**S-04 — Klucze wiadomości efemeryczne w pamięci** — Kompromitacja PostgreSQL bez dostępu do live procesu nie odszyfruje treści wiadomości.

**S-05 — Domenowo-separowane AAD** — Każde pole rekordu użytkownika ma unikalny prefix AAD.

**S-06 — Limity rozmiaru żądań** — body i headers max 1MB, ochrona przed memory exhaustion.

**S-07 — Walidacja timestamp w obu kierunkach** — Zapobiega replay starych i preloading przyszłych żądań.

**S-08 — Rotacja MK na żywo (MkRotator)** — Crash-consistent rotacja kluczy bez przestoju.

---

## Podsumowanie ustaleń

| ID   | Opis                                              | Klasyfikacja | Priorytet  |
|------|---------------------------------------------------|--------------|------------|
| P-01 | Non-CT porównanie HMAC sub w JWT weryfikacji      | Podatność    | Niski      |
| T-01 | Restart zeruje anti-replay i rate-limit           | Trade-off    | Operacyjny |
| T-02 | Klucze wiadomości w pamięci — utrata przy restart | Trade-off    | Non-goal   |
| T-03 | PlainFileMkProvider — MK serwera w pliku          | Trade-off    | Kontekst.  |
| T-04 | Brak TLS — oczekiwany reverse proxy               | Trade-off    | Kontekst.  |

---

*Audyt oparty na analizie statycznej kodu źródłowego i `lithium_assumptions.md`. Nie przeprowadzano testów dynamicznych. Patrz `lithium_core_audit.md` i `lithiumd_audit.md` dla audytów pozostałych warstw.*