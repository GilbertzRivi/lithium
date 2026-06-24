# Rozwój, budowanie i fuzzing

Praktyczny przewodnik po budowaniu i testowaniu repozytorium.

## Crate'y workspace

| Crate | Rola |
|-------|------|
| `lithium_core` | wspólna kryptografia, zarządzanie kluczami, typy sekretne, abstrakcje DB |
| `lithiumd` | lokalny daemon klienta; trzyma klucze, wystawia IPC |
| `lithiumg` | klient GUI (egui); rozmawia z `lithiumd` przez IPC |
| `lithiums` | serwer relay; REST na Poem + PostgreSQL |
| `lithium_itest` | testy integracyjne; współdzielone helpery w `src/`, binarki testowe w `tests/` |

## Budowanie

```bash
cargo build                        # cały workspace
cargo build -p lithium_core        # pojedynczy crate
cargo clippy -- -D warnings
cargo fmt
```

### Zależności systemowe (Linux)

Budowanie `lithiumd` linkuje GTK 3 i libappindicator na potrzeby systemowego zasobnika (tray). Bez nich budowa przerywa się na kroku pkg-config `*-sys`. Zainstaluj `libgtk-3-dev` i `libappindicator3-dev` (lub odpowiednik libayatana-appindicator).

## Feature flagi

| Crate | Feature | Domyślnie | Efekt |
|-------|---------|-----------|-------|
| `lithiums` | `tpm` | **wł.** (`default = ["tpm"]`) | `TpmMkProvider` — master key zapieczętowany w TPM; wymaga `tss-esapi` |
| `lithiums` | `fuzzing` | wył. | eksponuje `fuzz_api` do harnessów |
| `lithium_core` | `fuzzing` | wył. | eksponuje `parse_keyfile_fuzz`, `opaque_parse_fuzz` |
| `lithiumd` | `fuzzing` | wył. | eksponuje `fuzz_api`; derive `Arbitrary` dla `FuzzOp` |

Bez TPM serwer buduje się z `--no-default-features` (patrz [deploy-instructions.md](deploy-instructions.md)); w runtime można też wymusić provider plikowy przez `LITHIUM_MK_PROVIDER=plain`. Feature `fuzzing` **nie** podmienia RNG ani prymitywów kryptograficznych — dodaje wyłącznie publiczne wejścia parsujące dla fuzzera.

## Testy

```bash
cargo test                                        # wszystkie
cargo test -p lithium_core                        # testy crate'a
cargo test -p lithium_core name                   # pojedynczy test
cargo test -p lithium_itest --test daemon_basic   # jedna binarka itest
```

Testy integracyjne (`lithium_itest`) dzielą się na trzy zestawy w `tests/`: `server/` (serwer w izolacji), `daemon/` (daemon przeciw in-process `TestServer`) i `daemon_server_tests/` (dwa daemony przez prawdziwy serwer). Poszczególne binarki testowe i ich zakres opisują pliki w `lithium_itest/tests/`.

## Fuzzing

Cele fuzzingowe (`cargo-fuzz`) leżą w `fuzz/fuzz_targets/`, korpusy w `fuzz/corpus/`. Każdy cel woła wejście parsujące eksponowane przez feature `fuzzing` odpowiedniego crate'a (np. `parse_keyfile_fuzz`, `opaque_parse_fuzz`, moduły `fuzz_api`).

```bash
cargo +nightly fuzz run <target>
```

Dostępne cele: `aead_decrypt`, `e2e_session_seq`, `identity_decode`, `invite_decode`, `keyfile_parse`, `kyberbox_decrypt`, `opaque_parse`, `pow_verify`, `secret_json`, `sign_verify`, `transport_decode`, `transport_micro`, `unpack_wire`.

Cele celują w powierzchnie parsujące nieufne wejścia: dekodowanie formatów wire (`unpack_wire`, `transport_decode`, `identity_decode`, `invite_decode`), deszyfrowanie (`aead_decrypt`, `kyberbox_decrypt`), parsowanie plików kluczy (`keyfile_parse`), OPAQUE (`opaque_parse`), weryfikację podpisów i PoW (`sign_verify`, `pow_verify`) oraz sekwencje stanu sesji E2E (`e2e_session_seq`).
