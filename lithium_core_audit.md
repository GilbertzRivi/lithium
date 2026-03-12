# Audyt kryptograficzny i bezpieczeństwa — `lithium_core`

**Wersja audytu:** 2.0
**Data:** 2026-03-12
**Zakres:** krata `lithium_core` — cały kod źródłowy
**Podstawa klasyfikacji:** `lithium_assumptions.md`

---

## Metodologia

Każde ustalenie klasyfikowane jest zgodnie z `lithium_assumptions.md`:

- **Podatność** — łamie założenia bezpieczeństwa Lithium
- **Trade-off** — zgodne z modelem, ale operacyjnie kosztowne
- **Non-goal** — coś, czego Lithium celowo nie zapewnia
- **Obserwacja** — neutralna, informacyjna

Weryfikacja każdego ustalenia opiera się na czytaniu kodu źródłowego, nie na założeniach.

---

## Podsumowanie wykonawcze

Implementacja kryptograficzna `lithium_core` jest poprawna w miejscach krytycznych. Wybory algorytmów, hierarchia kluczy, protokół rotacji i zarządzanie sekretami są spójne z threat model projektu.

Po pełnej analizie kodu: **dwie realne podatności** (design typów sekretnych), **jeden trade-off** operacyjny i kilka obserwacji. Poprzednia wersja tego audytu przeceniała priorytet P-02 i P-03 (nie są aktywnie eksploitowane) oraz błędnie klasyfikowała T-02 i T-03 jako trade-offy — są to cechy projektowe.

---

## 1. Architektura kryptograficzna — analiza poprawności

### 1.1 Hybrydowe szyfrowanie KyberBox

**Plik:** `lithium_core/src/crypto/kyberbox.rs`

KyberBox implementuje szyfrowanie hybrydowe łączące X25519 (ECDH) z ML-KEM-1024 (Kyber). Schemat:

```
seed_plain = random_32()
ecdh_key   = HKDF(ECDH(priv_x, peer_pub_x), salt=None, info="{ctx}/ecdh-key/v1")
seed_enc   = KyberKEM-DEM(peer_kyber_pub, seed_plain, aad="{ctx}/seed/v1")
base_key   = HKDF(ecdh_key, salt=seed_plain, info="{ctx}/base-key/v1")
body_key   = HKDF(base_key, salt=None, info="{ctx}/body-key/v1")
headers_key= HKDF(base_key, salt=None, info="{ctx}/headers-key/v1")
enc_body   = AES-256-GCM-SIV(body, body_key, rand_nonce, "{ctx}/body/v1")
enc_headers= AES-256-GCM-SIV(headers, headers_key, rand_nonce, "{ctx}/headers/v1")
```

Konstrukcja jest kryptograficznie poprawna. `base_key = HKDF(ikm=ecdh_key, salt=seed_plain)` — atakujący znający `ecdh_key` bez `seed_plain` (chronionego przez Kyber) nie może wyznaczyć `base_key`, bo w HKDF salt pełni rolę klucza HMAC. Analogicznie w drugą stronę. Zapewnia bezpieczeństwo gdy przynajmniej jeden komponent (ECDH lub KEM) jest bezpieczny — poprawna implementacja algorytmicznej agility.

**KEM-DEM w Kyber seed encryption:** `SHA256(ciphertext)` jako sól HKDF to standardowy wzorzec (analogiczny do HPKE RFC 9180). AAD wiąże szyfrogram AEAD z konkretnym szyfrogramem KEM — podmiana KEM ciphertext zostanie wykryta. Poprawne.

### 1.2 Hierarchia kluczy w plikach kluczy

**Plik:** `lithium_core/src/keys/keyfile.rs`

```
KEYF | version | alg_id | dek_len
  || salt (32B)
  || nonce_wrap (12B) + AES-GCM-SIV(DEK, key=KEK, aad=keyfile:v1|key_type)
  || nonce_payload (12B) + AES-GCM-SIV(payload, key=DEK, aad=keyfile:v1|key_type)

gdzie: KEK = HKDF(MK, salt, "kek/v1")
       DEK = random_32()
```

Dwuwarstwowa hierarchia MK → KEK → DEK jest prawidłowym wzorcem: umożliwia rotację MK (rewrap DEK) bez re-szyfrowania payloadu. Nonce'y dla wrap i payload są niezależne. Każde wywołanie generuje nowy losowy DEK i nowy salt. AAD `keyfile:v1|{key_type}` zapewnia separację domenową. `write_secure` używa atomic rename po fsync (tmp → rename). `rewrap_keyfile_dek_to_bytes` zeroizuje stare pole salt/nonce/ct_wrap przed zwróceniem. Poprawne.

### 1.3 AEAD

**Plik:** `lithium_core/src/crypto/aead.rs`

AES-256-GCM-SIV z losowymi nonce'ami (96-bit, `SysRng`). Misuse-resistant: kolizja nonce nie złamie autentyczności. Format: `version(1) || nonce(12) || ct+tag`. Poprawne.

### 1.4 KDF

**Plik:** `lithium_core/src/crypto/kdf.rs`

Prosta owijka HKDF-SHA256. `None` jako sól = zero-salt (RFC 5869) — bezpieczne gdy IKM jest kryptograficznie silnym sekretem. Poprawne.

### 1.5 Podpisy cyfrowe

**Plik:** `lithium_core/src/crypto/sign.rs`

Ed25519 (`ed25519-dalek` z feature `zeroize`) + ML-DSA-87 (`pqcrypto`). Dual-sign bez short-circuit w weryfikacji (obie sygnatury zawsze obliczane — brak timing oracle przez early return). Biblioteki z potwierdzoną implementacją — brak własnej kryptografii. Poprawne.

### 1.6 Protokół rotacji kluczy — crash-consistency

**Plik:** `lithium_core/src/keys/manager.rs`, funkcja `maybe_rotate_mk`

Protokół (kroki 1–9):
1. `next-mk-old.keyf` ← new_mk zaszyfrowany pod old_mk
2. `next-mk-new.keyf` ← new_mk zaszyfrowany pod new_mk
3. fsync katalogu `.rotate/`
4. Staging: przepisanie wszystkich keyfile'ów z nowym DEK-wrap
5. Marker `ready`
6. Apply: przepisanie plików live
7. `mk_provider.store_mk(new_mk)`
8. Rotacja `jwt_secret`
9. Cleanup `.rotate/`

| Awaria po kroku | Odzysk |
|---|---|
| 3 (przed markerem) | Brak `ready` → `cleanup_rotation_dir` → restart bez rotacji |
| 5 (po markerze, przed apply) | current_mk=old_mk → `next-mk-old.keyf` → new_mk → apply → store_mk |
| 6 (częściowy apply) | j.w., apply idempotentne ze staged |
| 6 (pełny apply, przed store_mk) | j.w. |
| 7 (po store_mk, przed cleanup) | current_mk=new_mk → `next-mk-new.keyf` → provider_already_switched=true → cleanup |

Protokół jest crash-consistent. `KeyManager` jest typowo owinięty `Arc<Mutex<...>>` — mutex eliminuje race condition TOCTOU między rotacją a `derive_secret32`.

---

## PODATNOŚCI

### P-01 — `FixedBytes<N>::PartialEq` nie jest constant-time

**Plik:** `lithium_core/src/secrets/bytes.rs:94`
**Klasyfikacja:** Podatność — Średni

```rust
impl<const N: usize> PartialEq for FixedBytes<N> {
    fn eq(&self, other: &Self) -> bool { self.as_array() == other.as_array() }
}
```

`[u8; N] == [u8; N]` może zakończyć porównanie przy pierwszym różnym bajcie (timing side-channel). `FixedBytes<N>` jest typem bazowym dla `Byte32` (tokeny sesji, klucze, identyfikatory), `Byte12` (nonce'y), `MasterKey32`, `SessionId32`.

**Weryfikacja aktualnego stanu kodu:** Przeszukanie całego repozytorium nie wykazało miejsc, w których `FixedBytes::PartialEq` (`==` operator) jest aktualnie używany do porównania wartości sekretnych w ścieżkach bezpieczeństwa. Porównanie soli w `kyberbox.rs` dotyczy danych publicznych (O-02). Ryzyko jest **latentne** — implementacja `PartialEq` jest niebezpieczna jako interfejs, nawet jeśli nie jest aktualnie eksploitowana.

**Rekomendacja:**
```rust
impl<const N: usize> PartialEq for FixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}
```
Zmiana jednolinijkowa eliminująca całą kategorię timing attacks dla wszystkich obecnych i przyszłych callerów.

---

### P-02 — `SecretBytes::into_vec()` zwraca niezeroizowany `Vec<u8>`

**Plik:** `lithium_core/src/secrets/bytes.rs:133`
**Klasyfikacja:** Podatność — Niski (nieużywana niebezpieczna API)

```rust
pub fn into_vec(self) -> Vec<u8> { self.0.expose_secret().clone() }
```

Klonuje wewnętrzny `Vec<u8>` — oryginał jest zeroizowany przy dropie `SecretBox`, ale kopia w zwróconym `Vec` pozostaje bez gwarancji wyzerowania.

**Weryfikacja aktualnego stanu kodu:** `into_vec()` nie jest nigdzie wywoływane w całym repozytorium. Jest to niebezpieczna API bez aktualnych użytkowników — ryzyko materializuje się przy przyszłych callerach.

**Rekomendacja:** Zmienić sygnaturę na `fn into_vec(self) -> Zeroizing<Vec<u8>>` lub przemianować na `into_vec_unchecked()` z dokumentacją nakładającą odpowiedzialność za zeroizację na callera.

---

## TRADE-OFFY

### T-01 — `PlainFileMkProvider` przechowuje Master Key serwera bez ochrony hasłem

**Plik:** `lithium_core/src/keys/manager.rs:84–93`
**Klasyfikacja:** Trade-off — Wysoki operacyjnie

MK serwera jako 32 surowe bajty w pliku (0o600). Kompromitacja systemu plików → odczyt MK → odszyfrowanie wszystkich plików kluczy serwera → możliwość podszywania się pod serwer.

**Uzasadnienie:** Serwer nie ma użytkownika do wpisania hasła przy starcie. Alternatywy (HSM, Vault, systemd-creds) poza zakresem MVP. Serwer jest z definicji niezaufany dla poufności komunikacji E2E.

**Rekomendacja operacyjna:** Szyfrowanie dysku, uprawnienia 0700 na `LITHIUM_KEYS_DIR`, monitoring dostępu do pliku MK. Patrz `lithiums_audit.md` T-03 dla pełnego kontekstu wdrożeniowego.

---

## NON-GOALS (nie raportowane jako błędy)

| Właściwość | Dlaczego nie jest Trade-offem/Podatnością |
|---|---|
| JWT secret efemeryczny (rotacja co godzinę, brak persystencji) | Celowa decyzja: `keys::random_32()` przy każdym `start()`, rotacja w `maybe_rotate_mk()`. Unieważnienie sesji przy restarcie = świadomy wybór bezpieczeństwa nad wygodą |
| Argon2id p=1 | m=64 MiB, t=3, p=1 przekracza minimum OWASP (m=19, t=2, p=1). p=1 to najkonkretniejszy wybór dla odporności na ataki sprzętowe; nie jest słabością |
| `derive_wrap_key` bez wewnętrznej walidacji długości | Funkcja prywatna wywoływana wyłącznie przez `wrap_dek_for_server_hex`/`unwrap_dek_from_server_hex`, które operują na sekretach już zwalidowanych przez `validate_password`. Brak ryzyka w aktualnym kodzie |

---

## OBSERWACJE

### O-01 — `SecretJson::zeroize_value` — niepełna zeroizacja `Value::Number`

**Plik:** `lithium_core/src/secrets/json.rs`

```rust
Value::Number(_) => *v = Value::Null,
```

Przypisanie `Null` zmienia discriminant, ale stare bajty wartości numerycznej mogą pozostać w pamięci. `Value::String` jest zeroizowany poprawnie.

**Kontekst Lithium:** Sekrety w JSON to klucze i hasła (stringi). Liczby w payload JSON to: znaczniki czasu (publiczne), liczniki — nie są to tajemnice. Aktualny `SecretJson` nie przechowuje wrażliwych wartości numerycznych. Warto udokumentować ograniczenie w kodzie.

---

### O-02 — Non-CT salt check w kyberbox

**Plik:** `lithium_core/src/crypto/kyberbox.rs`

Porównanie `salt_ref != salt` na danych publicznych (przesyłanych cleartext). Nie jest podatnością.

---

### O-03 — `FixedBytes::Hash` ujawnia bajty sekretów do hashera

**Plik:** `lithium_core/src/secrets/bytes.rs:97–99`

`Hash` karmi bajty sekretu do hashera sekwencyjnie. Używane dla `FixedBytes` jako klucze HashMap — aktualnie dla identyfikatorów, nie tajemnic. Akceptowalne, warte dokumentacji.

---

### O-04 — Generowanie kluczy PQC przez wewnętrzny RNG pqcrypto

**Plik:** `lithium_core/src/crypto/keys.rs:44–52`

ML-KEM-1024 i ML-DSA-87 generowane przez `mlkem1024::keypair()` / `mldsa87::keypair()` z wewnętrznym `randombytes()` (getrandom backend). W odróżnieniu od kluczy klasycznych (explicit `SysRng`). Poprawne, asymetria warta dokumentacji dla przyszłych audytorów.

---

### O-05 — Tymczasowe kopie stosu na granicy SecretBox/C-ABI

**Plik:** `lithium_core/src/crypto/kyberbox.rs`, `keys/manager.rs`

```rust
let my_secret = XStaticSecret::from(*priv_x.as_array()); // kopia 32B na stosie
```

Kopia stosu przed konstruktorem `XStaticSecret`. `XStaticSecret` zeroizuje przy dropie, kopia stosu — nie (nadpisana przy kolejnych alokacjach). Standardowa trudność safe-Rust / C ABI, nie jest praktycznie exploitowalna.

---

## Mocne strony implementacji

**S-01 — Poprawna hybrydyzacja PQ + klasyczna kryptografia.** KyberBox łączy X25519 i ML-KEM-1024 przez HKDF (jeden komponent jako IKM, drugi jako sól) — nie naiwna konkatenacja.

**S-02 — AES-256-GCM-SIV eliminuje kategorię błędów nonce-reuse.** Kolizja nonce nie złamie autentyczności.

**S-03 — Dwuwarstwowa hierarchia klucza (MK → KEK → DEK).** Rotacja MK nie wymaga re-szyfrowania payloadu. Wyciek jednego DEK nie ujawnia innych kluczy.

**S-04 — Crash-consistent protokół rotacji z dwoma kopiami nowego MK.** Idempotentne apply z marker-based recovery.

**S-05 — Atomowe zapisy z fsync.** `write_secure`: tmp → fsync → rename. Plik nigdy nie istnieje z błędnymi uprawnieniami (0o600 przed zapisem treści).

**S-06 — Systematyczne zarządzanie sekretami przez `SecretBox` + `zeroize`.** `FixedBytes<N>`, `SecretBytes`, `SecretString`, `SecretJson` owijają dane w `SecretBox`. `Debug`/`Display` nie ujawniają zawartości.

**S-07 — Separacja domenowa we wszystkich KDF.** Wszystkie etykiety zawierają kontekst i wersję — brak możliwości cross-context key confusion.

**S-08 — Tłumienie informacji w błędach produkcyjnych.** `cfg!(debug_assertions)` — szczegóły błędów tylko w debug build.

**S-09 — `EphemeralStoreManager` zeroizuje wpisy przy usunięciu/TTL.** `cleanup_once`, `take`, `del` — wszystkie ścieżki usunięcia zeroizują `SecretBytes` przed dropem.

---

## Tabela ustaleń

| ID | Klasyfikacja | Opis | Priorytet |
|---|---|---|---|
| P-01 | Podatność | `FixedBytes<N>::PartialEq` — non-constant-time (latent) | Średni |
| P-02 | Podatność | `SecretBytes::into_vec()` — brak zeroizacji zwróconego Vec (nieużywane) | Niski |
| T-01 | Trade-off | `PlainFileMkProvider` — MK serwera plaintext na dysku | Wysoki operacyjnie |
| O-01 | Obserwacja | `SecretJson` — niepełna zeroizacja `Value::Number` (brak sekretów numerycznych w praktyce) | Informacyjny |
| O-02 | Obserwacja | Non-CT salt check w kyberbox (dane publiczne) | Informacyjny |
| O-03 | Obserwacja | `FixedBytes::Hash` — karmi bajty sekretów do hashera | Informacyjny |
| O-04 | Obserwacja | PQC keypair generation przez wewnętrzny RNG pqcrypto (poprawne) | Informacyjny |
| O-05 | Obserwacja | Tymczasowe kopie stosu na granicy SecretBox/C-ABI | Informacyjny |

---

## Priorytety napraw

**P-01 (pilne):** Wymienić `PartialEq` na `subtle::ConstantTimeEq` — zmiana jednolinijkowa eliminująca całą kategorię timing attacks prewencyjnie dla wszystkich przyszłych callerów.

**P-02 (niezbędne):** Zmienić `into_vec()` → `Zeroizing<Vec<u8>>` lub dodać `_unchecked` w nazwie z dokumentacją.

**T-01 (operacyjne):** Dokumentacja wdrożeniowa: szyfrowanie dysku, monitoring dostępu do pliku MK.

---

*Audyt oparty na analizie statycznej całego kodu źródłowego. Nie przeprowadzano testów dynamicznych. Patrz `lithiums_audit.md` i `lithiumd_audit.md` dla audytów pozostałych warstw.*