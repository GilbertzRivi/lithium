# lithium_core

Wspólna biblioteka kryptograficzna, typów sekretnych i zarządzania kluczami dla projektu Lithium.

Lithium jest komunikatorem zaprojektowanym dla środowisk, w których serwer, operator i infrastruktura mogą
być całkowicie niegodne zaufania. Celem projektu nie jest wygoda — celem jest matematyczne ograniczenie 
możliwości ujawnienia danych nawet przez operatora. `lithium_core` realizuje wszystkie kryptograficzne
podstawy tego modelu.

## Miejsce w architekturze

```
lithiumg (GUI)
  ↕ IPC
lithiumd (daemon)          ← używa lithium_core
  ↕ HTTPS
lithiums (serwer)          ← używa lithium_core
```

`lithium_core` jest zależnością wspólną dla `lithiumd` i `lithiums`. Zawiera wszystko, co nie jest specyficzne
dla jednej warstwy: kryptografię, typy sekretne, zarządzanie kluczami i bazę danych.

## Moduły

### `crypto` — operacje kryptograficzne

#### `crypto::aead` — szyfrowanie symetryczne

Szyfrowanie AES-256-GCM-SIV z uwierzytelnionym szyfrogramem (AEAD).

```
encrypt_raw(plaintext, key, nonce, aad) -> SecretBytes   // surowy AES-256-GCM-SIV
decrypt_raw(ciphertext, key, nonce, aad) -> SecretBytes

encrypt(plaintext, key, nonce, aad) -> SecretBytes       // blob z wersją i nonce
decrypt(blob, key, aad) -> SecretBytes                   // parsuje blob automatycznie
```

Format blobów `encrypt`:
```
[version: u8 = 1][nonce: 12 bytes][ciphertext + tag: N bytes]
```

AAD jest zawsze wymagane — błędne lub puste AAD powoduje błąd deszyfrowania.

#### `crypto::kdf` — wyprowadzanie kluczy

HKDF-SHA256. Jedno wywołanie wyprowadza 32 bajty klucza.

```
derive32(input, salt, info) -> Byte32
```

`salt` jest opcjonalne. `info` jest zawsze wymagane i służy separacji domen.

#### `crypto::sign` — podpisy cyfrowe

Dual-signature: każda wiadomość jest podpisywana jednocześnie klasycznie i post-kwantowo.

```
// Ed25519 (klasyczny)
sign_message(message, priv_ed_seed) -> SecretBytes       // 64 bajty
verify_signature(message, signature, pub_key) -> bool

// ML-DSA-87 / Dilithium (post-kwantowy)
sign_message_dili(message, dili_sk_bytes) -> SecretBytes
verify_signature_dili(message, signature, dili_pk_bytes) -> bool
```

#### `crypto::keys` — generowanie materiału kryptograficznego

Generatory par kluczy i losowego materiału. Wszystkie używają systemowego CSRNG (`SysRng`).

```
random_fixed::<N>() -> FixedBytes<N>
random_12() -> Nonce12
random_32() -> SessionId32
random_master_key32() -> MasterKey32

random_x25519_keypair() -> (FixedBytes<32>, FixedBytes<32>)      // (seed_sk, pk)
random_ed25519_keypair() -> (FixedBytes<32>, FixedBytes<32>)     // (seed, pk)
random_kyber_mlkem1024_keypair() -> (SecretBytes, SecretBytes)   // (sk, pk)
random_dilithium_mldsa87_keypair() -> (SecretBytes, SecretBytes) // (sk, pk)
```

#### `crypto::kyberbox` — hybrydowe szyfrowanie asymetryczne

`kyberbox` to własny schemat KEM+DEM łączący X25519 (ECDH) z ML-KEM-1024 (Kyber).
Bezpieczeństwo zależy od obu algorytmów jednocześnie — złamanie jednego nie kompromituje szyfrowania.

Schemat dla jednej wiadomości:

```
1. ECDH: shared = X25519(priv_x, peer_pub_x)
2. ecdh_key = HKDF(shared, info="{ctx}/ecdh-key/v1")
3. seed_plain = random_32()
4. seed_enc = KEM-DEM(peer_kyber_pub, seed_plain)   // ML-KEM-1024 + AES-256-GCM-SIV
5. base_key = HKDF(ecdh_key, salt=seed_plain, info="{ctx}/base-key/v1")
6. body_key = HKDF(base_key, info="{ctx}/body-key/v1")
7. headers_key = HKDF(base_key, info="{ctx}/headers-key/v1")
8. enc_body = AES-256-GCM-SIV(body, body_key)
9. enc_headers = AES-256-GCM-SIV(headers, headers_key)
```

Format wyjściowy `WirePayload`:

```rust
pub struct WirePayload {
    pub enc_body: SecretBytes,
    pub enc_headers: SecretBytes,
    pub seed_enc: SecretBytes,   // KEM ciphertext + zaszyfrowany seed
}
```

Format wewnętrzny `seed_enc`:
```
[ver: u8][kem_id: u8][aead_id: u8][salt_len: u8][salt: 32 bytes]
[ct_len: u16][kyber_ciphertext: N bytes][aead_blob: M bytes]
```

Identyfikatory wersji i algorytmów są zakodowane w AAD i weryfikowane 
przy deszyfrowaniu — podmiana algorytmu skutkuje błędem autentyczności.

Interfejs:

```
encrypt(ctx, priv_x, peer_pub_x, peer_k_pub, body, headers) -> WirePayload
decrypt(ctx, priv_x, peer_pub_x, kyber_priv, wire) -> (body, headers)
```

`ctx` jest ciągiem kontekstu oddzielającym domeny (np. `"shake"`, `"session"`).

---

### `keys` — zarządzanie kluczami

#### `keys::manager` — `KeyManager<P>`

Centralny komponent zarządzający całym materiałem kryptograficznym jednej tożsamości 
(serwera lub użytkownika). Kluczowy element bezpieczeństwa — przechowuje klucze 
prywatne zaszyfrowane Master Key, obsługuje rotację MK i odzysk przerwanej rotacji.

**Struktura katalogów na dysku:**

```
{base_dir}/{kind}/{name}/
├── pub/
│   ├── ed25519.pub
│   ├── x25519.pub
│   ├── kyber-mlkem1024.pub
│   └── dilithium-mldsa87.pub
├── priv/
│   ├── ed25519.keyf          ← zaszyfrowany plik keyfile
│   ├── x25519.keyf
│   ├── kyber-mlkem1024.keyf
│   └── dilithium-mldsa87.keyf
├── secrets/
│   └── {hex_label}.keyf     ← arbitralne sekrety pochodne
├── .rotate/                 ← katalog tymczasowy rotacji MK
│   ├── next-mk-old.keyf
│   ├── next-mk-new.keyf
│   ├── staged/              ← pliki przed zatwierdzeniem
│   └── ready                ← marker gotowości
└── mk                       ← Master Key (PlainFileMkProvider)
```

**Rotacja Master Key:**

Rotacja MK jest atomowa i crash-safe. Protokół:

1. Zapisz stary i nowy MK w `.rotate/` (oba zaszyfrowane).
2. Przygotuj wszystkie pliki `.keyf` ze starym opakowaniem i nowym opakowaniem w `.rotate/staged/`.
3. Zapisz marker `.rotate/ready`.
4. Zastosuj pliki staged do lokalizacji docelowych.
5. Zaktualizuj MK u providera.
6. Usuń katalog `.rotate/`.

Przy starcie `KeyManager` sprawdza czy istnieje niedokończona rotacja i próbuje ją 
dokończyć lub wycofać, zanim załaduje klucze. Domyślny interwał rotacji to **3600 sekund** (1 godzina).

**Trait `MkProvider`:**

```rust
pub trait MkProvider {
    fn load_mk(&self) -> Result<Byte32>;
    fn store_mk(&self, mk: &Byte32) -> Result<()>;
    fn derive_secret32(&self, mk: &Byte32, label: &[u8]) -> Result<Byte32>;
}
```

Domyślna implementacja `PlainFileMkProvider` przechowuje MK jako plik binarny. 
Trait jest pluggable — `lithiumd` może podłączyć własny provider oparty
na haśle użytkownika i komponencie serwerowym.

**API:**

```rust
// Inicjalizacja
KeyManager::start(base_dir, kind, name, mk_provider) -> Result<KeyManager<P>>
KeyManager::start_plain(base_dir, kind, name) -> Result<KeyManager<PlainFileMkProvider>>

// Dostęp do kluczy prywatnych (callback pattern — klucz nie opuszcza scope)
manager.with_ed_sk(|seed| { ... }) -> Result<R>
manager.with_x25519_sk(|seed| { ... }) -> Result<R>
manager.with_kyber_sk(|sk| { ... }) -> Result<R>
manager.with_dilithium_sk(|sk| { ... }) -> Result<R>
manager.with_x25519_and_kyber_sk(|x_seed, kyber_sk| { ... }) -> Result<R>

// Klucze publiczne
manager.public_keys() -> &PublicKeys

// Sekrety pochodne (label-based)
manager.derive_secret32(label: &[u8]) -> Result<Byte32>

// JWT secret (rotowany razem z MK)
manager.jwt_secret() -> &Byte32

// Rotacja
manager.maybe_rotate_mk() -> Result<()>
```

**`PublicKeys`:**

```rust
pub struct PublicKeys {
    pub ed25519: Byte32,
    pub x25519: Byte32,
    pub kyber: SecretBytes,
    pub dilithium: SecretBytes,
}
```

#### `keys::keyfile` — format pliku klucza

Własny format binarny `.keyf` implementujący envelope encryption:

```
[KEYF magic: 4 bytes][version: u8][alg_id: u8][dek_len: u16]
[salt_len: u16][salt: 32 bytes]
[nonce_wrap_len: u16][nonce_wrap: 12 bytes]
[ct_wrap_len: u16][ct_wrap: N bytes]        ← AES-256-GCM-SIV(DEK, KEK)
[nonce_payload_len: u16][nonce_payload: 12 bytes]
[ct_payload_len: u32][ct_payload: M bytes]  ← AES-256-GCM-SIV(secret, DEK)
```

Schemat szyfrowania:
- **KEK** = HKDF(MasterKey, salt, info=`"kek/v1"`)
- **DEK** = losowy 32-bajtowy klucz na plik
- Payload jest szyfrowany DEK-iem, DEK jest szyfrowany KEK-iem
- AAD zawiera wersję i typ klucza (`"keyfile:v1|{key_type}"`) — błędny typ skutkuje błędem deszyfrowania

Zapis przez `write_secure` używa wzorca `tmp + rename` z `fsync` i uprawnieniami `0o600` (Unix).

Rewrapping (zmiana MK bez deszyfrowania payloadu):

```
rewrap_keyfile_dek(path, old_mk, new_mk, key_type) -> Result<()>
rewrap_keyfile_dek_to_bytes(path, old_mk, new_mk, key_type) -> Result<SecretBytes>
```

---

### `secrets` — typy sekretne

Wszystkie typy sekretne zapewniają:
- Brak implementacji `Display`/`Debug` ujawniającej zawartość (wypisują `<redacted>` lub `FixedBytes<N>(..)`).
- Zeroizację pamięci przy `Drop` (przez `secrecy::SecretBox` + `zeroize`).
- Brak automatycznej konwersji do `String` ani serializacji do logów.

#### `FixedBytes<N>` i aliasy

Stałej długości bufor sekretny. Przechowywany w `SecretBox<[u8; N]>`.

```rust
pub type Byte12 = FixedBytes<12>;   // nonce
pub type Byte32 = FixedBytes<32>;   // klucz, seed, hash
pub type Byte64 = FixedBytes<64>;   // sygnatura Ed25519
pub type Byte2048 = FixedBytes<2048>;
```

Wybrane metody:
```rust
FixedBytes::new(bytes: [u8; N]) -> Self
FixedBytes::from_slice(slice: &[u8]) -> Result<Self>
FixedBytes::from_hex(s: &str) -> Result<Self>    // wymaga lowercase, odrzuca prefiks 0x
FixedBytes::new_zeroed() -> Self
FixedBytes::to_hex() -> SecretString
FixedBytes::as_array() -> &[u8; N]
FixedBytes::as_slice() -> &[u8]
```

#### `SecretBytes`

Sekretny bufor zmiennej długości. Przechowywany w `SecretBox<Vec<u8>>`.

```rust
SecretBytes::new(v: Vec<u8>) -> Self
SecretBytes::from_slice(v: &[u8]) -> Self
SecretBytes::from_hex(s: &str) -> Result<Self>
SecretBytes::as_slice() -> &[u8]
SecretBytes::to_hex() -> SecretString
```

#### `SecretString`

Sekretny ciąg UTF-8. Implementuje `Display` jako `<redacted>`.

```rust
SecretString::new(s: String) -> Self
SecretString::new_checked(s: String) -> Result<Self>   // odrzuca null bytes
SecretString::expose() -> &str                          // jedyna metoda dostępu
SecretString::from_utf8_bytes(bytes: &[u8]) -> Result<Self>
SecretString::decode_hex() -> Result<Zeroizing<Vec<u8>>>
SecretString::decode_hex_fixed::<N>() -> Result<FixedBytes<N>>
```

#### `SecretJson`

Sekretny dokument JSON z zeroizacją przy `Drop`. Rekurencyjnie zeroizuje wszystkie stringi i klucze obiektu.

```rust
SecretJson::from_str(s: &str) -> Result<Self>
SecretJson::from_bytes(bytes: &[u8]) -> Result<Self>
SecretJson::get_string(key) -> Result<SecretString>
SecretJson::get_integer(key) -> Result<SecretBox<i64>>
SecretJson::get_bool(key) -> Result<bool>
SecretJson::take_string(key) -> Result<SecretString>   // usuwa pole z mapy
SecretJson::with_exposed(|value| { ... }) -> R         // dostęp do serde_json::Value
```

#### Aliasy typów (`secrets::types`)

```rust
pub type MasterKey32 = Byte32;
pub type Nonce12 = Byte12;
pub type SessionId32 = Byte32;
```

---

### `passwords` — obsługa haseł

#### Hashowanie (Argon2id)

Parametry standardowe: pamięć 64 MB, 3 iteracje, 1 wątek, output 32 bajty.

```rust
hash_password_phc(password: &SecretString) -> Result<String>       // PHC string
verify_password_phc(phc: &str, password: &SecretString) -> Result<bool>
```

#### Walidacja hasła

```rust
pub struct PasswordPolicy {
    pub min_len: usize,          // default: 8
    pub max_len: usize,          // default: 1024
    pub require_lowercase: bool, // default: true
    pub require_uppercase: bool, // default: true
    pub require_digit: bool,     // default: true
    pub require_special: bool,   // default: true
    pub allow_whitespace: bool,  // default: false
}

validate_password(password: &SecretString, pol: PasswordPolicy) -> Result<()>
validate_passwords_distinct(a: &SecretString, b: &SecretString) -> Result<()>
```

#### DEK (Data Encryption Key) — owijanie hasłem

Schemat używany do przechowywania DEK-a na serwerze zaszyfrowanego hasłem danych:

```rust
generate_dek() -> Result<Byte32>
wrap_dek_for_server_hex(dek, data_password) -> Result<SecretString>   // hex blob
unwrap_dek_from_server_hex(blob_hex, data_password) -> Result<Byte32>
```

Format blobów DEK (hex-encoded):
```
[ver: u8 = 1][salt: 32 bytes][aead_blob: N bytes]
```

Klucz owijający = `Argon2id(data_password, salt)`. AAD = `"lithium/dek-wrap/v1"`.

---

### `db` — integracja z bazą danych

#### `db::DataManager<P>`

Fasada łącząca `DatabaseConnection` (SeaORM) z `KeyManager`. Zarządza szyfrowaniem blobów w bazie.

```rust
DataManager::new(db, key_manager) -> Self
manager.db() -> &DatabaseConnection
manager.load_db_dek() -> Result<Byte32>             // z etykiety "lithium/db-dek/v1"
manager.users_uuid_namespace() -> Result<Uuid>      // deterministyczny UUID namespace
manager.encrypt_db_blob(plaintext, aad) -> Result<SecretBytes>
manager.decrypt_db_blob(blob, aad) -> Result<SecretBytes>
```

DEK bazy danych jest wyprowadzany z MK przez `derive_secret32` z etykietą `b"lithium/db-dek/v1"`.
DEK jest przechowywany jako plik `.keyf` w katalogu `secrets/`. Rotacja MK **rewrapuje plik DEK-a** (podmienia
jego szyfrowanie na nowy MK), ale nie zmienia wartości samego klucza — dane w bazie pozostają
zaszyfrowane tym samym DEK-iem i nie wymagają ponownego szyfrowania.

UUID namespace użytkowników jest deterministyczny i wyprowadzany z MK — ta sama 
tożsamość zawsze generuje ten sam UUID dla danego loginu.

---

### `utils` — narzędzia pomocnicze

#### `utils::store` — `EphemeralStoreManager`

In-memory store z TTL i zeroizacją przy wygaśnięciu. Używany m.in. do przechowywania tymczasowych tokenów sesji.

```rust
store.set(key, value, ttl) -> Result<()>
store.set_if_absent(key, value, ttl) -> Result<bool>
store.peek(key) -> Result<Option<SecretBytes>>   // odczyt bez usunięcia
store.take(key) -> Result<Option<SecretBytes>>   // odczyt z usunięciem
store.del(key) -> Result<()>
```

Wewnętrzny goroutine (`tokio::spawn`) czyści wygasłe wpisy co 500 ms. Przy usuwaniu
wygasłego wpisu zawartość `SecretBytes` jest zeroizowana przed `drop`.

#### `utils::headers`

Narzędzia do parsowania nagłówków HTTP jako typów sekretnych.

```rust
header_str(headers, name) -> Result<SecretString>
header_hex::<N>(headers, name) -> Result<FixedBytes<N>>
header_hex_bytes(headers, name) -> Result<SecretBytes>
```

---

### `error` — obsługa błędów

```rust
pub type Result<T> = core::result::Result<T, LithiumError>;

pub struct LithiumError {
    pub kind: CryptoErrorKind,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
```

W trybie `debug_assertions` (`LithiumError::is_verbose()`) błędy wypisują szczegóły. 
W trybie release wypisują tylko kategorię — bez wewnętrznych szczegółów, które mogłyby wyciec przez logi.

Wybrane warianty `CryptoErrorKind`:
- `AeadFailed` — błąd deszyfrowania lub autentyczności
- `KdfFailed` — błąd wyprowadzania klucza
- `InvalidLength { expected, got }` — nieprawidłowa długość bufora
- `InvalidHex` / `HexMustBeLowercase` / `HexDisallowedPrefix` — błędy parsowania hex
- `StringPolicy` — naruszenie polityki hasła/stringa
- `InvalidCredentials { msg }` — błąd uwierzytelnienia
- `InvalidPermissions { msg }` — naruszenie uprawnień
- `Io` — błąd I/O
- `Internal` — błąd wewnętrzny (nie ujawnia szczegółów w release)

`From` jest zaimplementowane dla: `std::io::Error`, `hex::FromHexError`, `serde_json::Error`, 
`hkdf::InvalidLength`, `aes_gcm_siv::aead::Error`, `rand::rngs::SysError`.

---

## Zależności kryptograficzne

| Crate           | Wersja      | Rola                                       |
|-----------------|-------------|--------------------------------------------|
| `aes-gcm-siv`   | 0.11.1      | AEAD: AES-256-GCM-SIV                      |
| `hkdf`          | 0.12        | KDF: HKDF-SHA256                           |
| `sha2`          | 0.10.9      | SHA-256 (KDF salt, weryfikacja)            |
| `pqcrypto`      | 0.18.1      | ML-KEM-1024 (Kyber), ML-DSA-87 (Dilithium) |
| `ed25519-dalek` | 2.2.0       | Ed25519 (podpisy)                          |
| `x25519-dalek`  | 2.0.1       | X25519 (ECDH)                              |
| `argon2`        | 0.5.3       | Argon2id (hash haseł, DEK wrap)            |
| `zeroize`       | 1.8.2       | Zeroizacja pamięci                         |
| `secrecy`       | 0.10.3      | Typy sekretne (`SecretBox`)                |
| `rand`          | 0.10.0      | CSRNG (`SysRng`)                           |

Cały crate ma `#![forbid(unsafe_code)]`.

---

## Model bezpieczeństwa

`lithium_core` realizuje następujące właściwości bezpieczeństwa:

**Poufność kluczy prywatnych:** Klucze prywatne nigdy nie opuszczają `KeyManager`
jako wartości — dostęp jest wyłącznie przez callback (`with_ed_sk`, `with_kyber_sk` itp.), 
który ogranicza czas życia sekretnego materiału do zakresu wywołania.

**Separacja domen:** Wszystkie operacje KDF i AEAD używają unikalnych etykiet kontekstu 
(`info`/`aad`). Klucz wyprowadzony dla jednego kontekstu nie może być użyty w innym.

**Hybrydowość post-kwantowa:** Szyfrowanie (`kyberbox`) i podpisy (Ed25519 + ML-DSA-87) są hybrydowe. 
Bezpieczeństwo nie zależy wyłącznie od odporności na komputery kwantowe — oba algorytmy muszą być złamane jednocześnie.

**Zeroizacja:** `FixedBytes`, `SecretBytes`, `SecretString`, `SecretJson` zeroizują pamięć przy `Drop`. 
Pliki tymczasowe przy rewrappingu zeroizują stare klucze po użyciu.

**Crash-safety rotacji:** Niedokończona rotacja MK jest wykrywana i kończona (lub wycofywana) przy następnym starcie.

**Bezpieczeństwo I/O:** Zapis kluczowych plików używa atomicznego `tmp + rename` z `fsync` i uprawnieniami `0o600`.

**Opaque błędy w release:** `LithiumError` nie ujawnia szczegółów wewnętrznych w trybie release — tylko kategorię błędu.

---

## Non-goals

Zgodnie z modelem projektu, `lithium_core` celowo nie zapewnia:

- Recovery po utracie Master Key — brak klucza oznacza utratę danych.
- Synchronizacji kluczy między urządzeniami.
- Operacji w trybie offline bez dostępu do MK.
- Gwarancji dostarczenia wiadomości — to nie jest warstwa transportowa.

Brak tych właściwości jest celowy. Odzysk jest gorszy od utraty danych, 
jeśli alternatywą jest zmniejszenie bezpieczeństwa.