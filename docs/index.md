# Dokumentacja Lithium

## Audyt biblioteki `lithium_core` — zakres i kolejność czytania

Przedmiotem audytu jest **biblioteka `lithium_core`**, nie cały komunikator. Granicę wyznacza [`lithium_core-threat-model.md`](security/lithium_core-threat-model.md): co biblioteka gwarantuje, a co jest odpowiedzialnością wywołującego (autentyczność kluczy publicznych odbiorcy, unikalność labeli separacji domenowej, ochrona przed replay, transport). Centralnym produktem jest **hybrydowy kombinator KyberBox** — jego poprawność jest głównym ustaleniem.

**W zakresie:** dwa filary `lithium_core` — zarządzanie kluczami at-rest (`keys`, `secrets`) oraz szyfrowanie hybrydowe (`crypto`) — i helpery (`opaque`, `pow`, `passwords`, `utils::store`).

**Poza zakresem:** warstwy aplikacji — `lithiumd` (IPC, sesja E2E), `lithiums` (relay, transport REST, rate limiting), `lithiumg` (GUI). Biblioteka jest przez nie *konsumowana*; ich dokumenty ([`crypto-protocol.md`](protocol/crypto-protocol.md), [`ipc-reference.md`](protocol/ipc-reference.md), [`threat-model.md`](security/threat-model.md), [`security-model.md`](security/security-model.md)) są kontekstem użycia, nie celem audytu — opisują jednak *usage-contract*, którego trzyma się komunikator i którego dotrzymanie zakłada biblioteka.

**Kolejność czytania:**

1. [`lithium_core-threat-model.md`](security/lithium_core-threat-model.md) — granica audytu: gwarancje vs odpowiedzialność wywołującego.
2. [`combiner.md`](security/combiner.md) — **centralny deliverable**: konstrukcja kombinatora, porównanie z X-Wing, argument hybrydy i pytania **Q1–Q4 postawione wprost** do rozstrzygnięcia.
3. [`kyberbox.md`](security/kyberbox.md) — pełny przepływ wire/kluczy KyberBox oraz szczegółowe ryzyka na poziomie konstrukcji (sekcja „Otwarte ryzyka i pytania do audytora").
4. [`key-hierarchy.md`](security/key-hierarchy.md) + [`data-lifecycle.md`](security/data-lifecycle.md) — katalog kluczy (derywacja, przechowywanie, czas życia) i inwentarz danych at-rest.
5. [`lithium_core.md`](reference/lithium_core.md) — referencja API biblioteki moduł po module; oraz `lithium_core/README.md` i rustdoc (`cargo doc -p lithium_core`).

**Centralne pytania:** Q1–Q4 w [`combiner.md`](security/combiner.md) (salt z `SHA256(ct_kem)`, asymetria salt-vs-IKM gałęzi PQ, `ecdh_ss` jako IKM bez salta, filtr integralności przed decapsulacją) oraz lista ryzyk konstrukcyjnych w [`kyberbox.md`](security/kyberbox.md). To są zadeklarowane otwarte punkty — zakres, który audyt ma rozstrzygnąć.

**Reprodukowalność i pokrycie:**

- Build odtwarzalny: [`reproducible-build.md`](security/reproducible-build.md) + przypięcie wersji w [`development.md`](operations/development.md) (`Cargo.lock` + `rust-toolchain.toml` `1.96.0`).
- Wektory testowe (KAT): `lithium_core/tests/golden_tests.rs` (3 testy) na danych `tests/testdata/` (`kyberbox_golden_v1`, `mldsa87_verify_golden_v1`).
- Testy publicznego API `lithium_core`: `crypto_tests` (93), `secret_tests` (66), `password_tests` (21), `store_tests` (14).
- Fuzzing: 13 celów `cargo-fuzz` na powierzchniach parsujących nieufne wejścia — patrz [`development.md`](operations/development.md) (sekcja „Fuzzing").

## `security/` — model bezpieczeństwa i analiza kryptografii

- [security-model.md](security/security-model.md) — model zaufania, priorytety, założenia, świadome kompromisy, widoczność serwera per request, prymitywy, klasyfikacja ustaleń audytowych
- [threat-model.md](security/threat-model.md) — strukturalny model zagrożeń: klasy przeciwnika, ich zdolności, obrona i ryzyko rezydualne; gwarancje forward secrecy i post-compromise security warstwy E2E
- [lithium_core-threat-model.md](security/lithium_core-threat-model.md) — węższy model zagrożeń samej biblioteki `lithium_core`: granica między gwarancjami biblioteki a odpowiedzialnością wywołującego
- [kyberbox.md](security/kyberbox.md) — analiza bezpieczeństwa schematu KyberBox: przepływ kluczy, właściwości, założenia, otwarte ryzyka
- [combiner.md](security/combiner.md) — uzasadnienie kombinatora hybrydowego: konstrukcja, porównanie z X-Wing, argument bezpieczeństwa i pytania Q1–Q4 wprost do audytora (centralny deliverable)
- [key-hierarchy.md](security/key-hierarchy.md) — katalog i hierarchia wszystkich kluczy: derywacja, przechowywanie, czas życia, analiza wycieku
- [data-lifecycle.md](security/data-lifecycle.md) — cykl życia danych i inwentarz prywatności: gdzie spoczywają, retencja, kto co widzi
- [reproducible-build.md](security/reproducible-build.md) — reprodukowalny build klienta: piny, kontener, weryfikacja opublikowanej binarki względem źródła

## `reference/` — referencja komponentów

- [lithium_core.md](reference/lithium_core.md) — biblioteka: kryptografia, typy sekretne, zarządzanie kluczami, format plików kluczy
- [lithiumd.md](reference/lithiumd.md) — daemon klienta: IPC, E2E, mailbox, SQLite, PasswordFileMkProvider
- [lithiums.md](reference/lithiums.md) — serwer relay: REST API, middleware, transport, schemat PostgreSQL
- [lithiumg.md](reference/lithiumg.md) — GUI: maszyna stanów, model wątków

## `protocol/` — specyfikacje protokołu

- [crypto-protocol.md](protocol/crypto-protocol.md) — specyfikacja protokołu kryptograficznego: transport (Shake/Session), E2E (WireV1), mailbox, parowanie kontaktów
- [ipc-reference.md](protocol/ipc-reference.md) — referencja protokołu IPC daemona: format, autoryzacja, maszyna stanów, pełna lista komend, zmienne środowiskowe
- [versioning.md](protocol/versioning.md) — wersjonowanie formatów i filozofia ewolucji protokołu

## `operations/` — wdrożenie, runtime, budowanie

- [deploy-instructions.md](operations/deploy-instructions.md) — wdrożenie `lithiums`: zmienne środowiskowe, providery master key, Docker/Docker Compose
- [daemon-runtime.md](operations/daemon-runtime.md) — runtime daemona `lithiumd`: model procesu, system tray, cykl życia, endpoint IPC, zmienne środowiskowe, układ katalogu danych
- [development.md](operations/development.md) — budowanie, przypięcie wersji i powtarzalność (`Cargo.lock` + `rust-toolchain.toml`), zależności systemowe, feature flagi, testy, fuzzing

## Przekrojowe (korzeń `docs/`)

- [design-decisions.md](design-decisions.md) — rejestr decyzji projektowych („dlaczego"): uzasadnienia, odrzucone alternatywy, koszty
- [glossary.md](glossary.md) — słownik pojęć własnych Lithium

## Przegląd projektu

- [`README.md`](../README.md) — opis projektu, architektura, właściwości bezpieczeństwa, wdrożenie
