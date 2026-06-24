# Lithium — plan przedaudytowy + go-to-market

## A. Domknięcia przed audytem (z przeglądu kodu)

### A1. Rozjazd dokumentacji z kodem: ochrona przed replay (najważniejsze)
docs/kyberbox.md (linie 100, 102, 124) twierdzi, że session.rs NIE odrzuca powtórek na
poziomie krypto i że replay-detekcja leży wyłącznie w warstwie przechowywania (msg_id UNIQUE).
Cytat z linii 124: „ochrona przed replay leży natomiast nie w session.rs, lecz w warstwie przechowywania".

Kod mówi co innego: lithiumd/src/e2e/session.rs:71 ma peer_st.replay.check_and_record(hdr.step)
→ replayed_message_err(), jest ReplayWindow (sliding window na hdr.step, state.rs:117-145) i test
e2e_replay_is_rejected (session.rs:357). Git: window wszedł w 38a7532, doc ruszany później bez korekty.

Dla audytora podwójnie szkodliwe: albo zmarnuje czas na „lukę", której nie ma, albo straci zaufanie do
całego docs/. Trzeba zaktualizować kyberbox.md — opisać oba poziomy (window na step w session.rs +
dedup msg_id w storage) i ich interakcję.

### A2. Sprzeczność: „wersje przypięte w Cargo.lock" — a Cargo.lock nie jest w repo
kyberbox.md:13 i threat-model (klasa 8) mówią o pinowaniu zależności. Cargo.lock jest w .gitignore
(commit 161efb3 cargo lock untrack). Dla binarek konwencja jest odwrotna: Cargo.lock się commituje.
Bez niego audytor nie odtworzy zestawu zależności, a audit.yml działa na świeżo rozwiązanym locku.
→ Wróć z trackowaniem Cargo.lock. To jednocześnie prerequisite reproducible build (patrz C1) i część
odpowiedzi na „a jeśli zmuszą Ciebie".

### A3. Brak LICENSE
Brak pliku licencji. Blokuje „prywatne repo → zewnętrzny podmiot". Decyzja licencyjna jest teraz
biznesowa, nie formalna (patrz B6).

### A4. Brak SECURITY.md / polityki disclosure
Krótki SECURITY.md + link do docs/security-model.md (sekcja „Klasyfikacja ustaleń").

### A5. Luka doc: skonsolidowana sekcja FS/PCS
README (PL i EN) deklaruje twardo „FS per wiadomość" + „PCS" (README.md:176-179). kyberbox.md:104
jest uczciwszy: FS per-epoka, nie per-wiadomość (rx_x_priv współdzielony do odpowiedzi peera). Nigdzie
nie ma jawnego modelu PCS: klucze tożsamości (ed_priv/dili_priv) nigdy nie rotują → „odzysk po przejęciu
stanu" działa tylko wobec przeciwnika pasywnego; aktywny ma podpisy na zawsze i MITM-uje przyszłe reklamy
kluczy. Dodać dokument „Gwarancje FS/PCS warstwy E2E" (co widzi atakujący przejmujący self_state w chwili
T: przeszłość poza oknem 32 vs w oknie; przyszłość pasywny vs aktywny) i uzgodnić README.

### A6. Drobiazgi
- fuzz/Cargo.toml edition = "2021" vs 2024 reszta — ujednolić.
- Brak rust-toolchain.toml / MSRV — jedna linijka, prerequisite reproducible build (C1).
- docs/index.md OK; dopisać, że Cargo.lock to źródło pinów (po A2).

## B. Plan biznesowy: lithium_core jako biblioteka PQ

### B1. Pozycjonowanie
Nie „mam PQ" — ML-KEM mają RustCrypto i aws-lc-rs za darmo. Wedge: „poprawne, zaudytowane, hybrydowe
złożenie, dzięki któremu przejdziesz SWÓJ audyt bez zatrudniania kryptografa". Prawo wymusza migrację
(tworzy budżet + pilność); audyt + poprawność hybrydy to powód, dla którego wybiorą Ciebie zamiast
rolować własne i oblać. Pitch „PQ crypto" przegra z darmowym; pitch „correct-by-construction audited
hybrid" sprzedaje coś, czego nie mają.

### B2. Lewar regulacyjny
NIST FIPS 203/204/205 (sierpień 2024) = dokładnie ML-KEM-1024 + ML-DSA-87. BSI (DE) i ANSSI (FR)
rekomendują HYBRYDĘ klasyczne+PQ — Twoja postawa jest zalecaną europejską, nie dziwactwem. To
najmocniejszy, najbardziej konkretny argument w UE: „regulatorzy zalecają hybrydę, oto zaudytowana
hybryda w Ruście".

### B3. Combiner = crux kupowalności
base_key = HKDF(ecdh_key, salt=seed_plain) to AUTORSKI kombinator. Kryptograf kupującego zapyta:
„czemu nie X-Wing i czy Twój jest dowiedlnie poprawny?". X-Wing to ML-KEM-768 + X25519 — nie wkleisz
1:1 (jesteś na 1024), ale będą porównywać. Potrzebna ODPOWIEDŹ, nie adopcja. kyberbox.md już listuje
otwarte pytania (SHA256(ct_kem) jako salt, HKDF bez salta z wyjściem X25519 jako IKM) → dla biblioteki
te pytania stają się CENTRALNYM deliverable audytu, bo kombinator jest produktem. Audyt formalnie
błogosławiący kombinator = rzecz, którą realnie sprzedajesz.

### B4. Reorder audytu
Audytuj lithium_core jako BIBLIOTEKĘ, nie cały komunikator najpierw. Powierzchnia mniejsza i czystsza
(bez IPC/daemona/GUI/serwera) → audyt tańszy, ciaśniejszy, mocniejszy — i audytujesz dokładnie to, co
sprzedajesz. Wydzielenie liby i przygotowanie do audytu to ta sama robota.

### B5. Revenue (i czemu dalej „bez szefa")
Nie „sprzedaję kopie kodu". (a) licencja komercyjna na zamknięte użycie; (b) GŁÓWNY przychód: kontrakty
integracyjne/support „pomóż mi zmigrować na PQ" = konsulting na Twoich warunkach; (c) „audited build +
SLA" w subskrypcji. Biblioteka to lead-magnet i dowód kompetencji; pieniądz jest w integracji. To ten
sam plan co „niezależna konsultantka PQ" — biblioteka = wiarygodność, integracja = revenue, Ty = szefowa.

### B6. Licencja (specyfika biblioteki)
Przy bibliotece AGPL odstrasza firmy (alergia prawna na linkowanie AGPL do zamkniętego produktu).
Rozważ source-available + komercja, albo „darmowe dla OSS/ewaluacji, płatne dla komercji". To realnie
decyduje, czy enterprise w ogóle dotknie. Domyka otwarty punkt LICENSE (A3).

## C. Supply-chain hardening (odpowiedź na „a jeśli zmuszą Ciebie" + zaufanie do biblioteki)

Architektura zamyka koercję po stronie SERWERA (operator nie ma plaintextu — najmocniejszy argument
sprzedażowy, otwierać nim pitch). NIE zamyka koercji po stronie DYSTRYBUCJI KLIENTA: zmuszony, podpisany,
backdoorowany build. TCB wciąż = binarka klienta + kanał update + klucz podpisujący, a Ty to pojedynczy
punkt. Precedensy: Lavabit (zmuszony do umożliwienia przyszłego przechwytu, zamknął firmę), Apple vs FBI
(zmuszony do PODPISANIA złośliwego kodu). To „zmuś budowniczego", nie „zmuś czytelnika".

- C1. Reproducible build — każdy weryfikuje, że opublikowana binarka = publiczne źródło. Prerequisite:
  Cargo.lock (A2) + rust-toolchain pin (A6) + kontener buildowy. Zmuszony backdoor nie zreprodukuje się.
- C2. Binary transparency log — append-only publiczny log artefaktów (Sigstore / CT-style). Targetowany
  podstawiony build niemożliwy bez publicznego śladu; zmuszony update staje się wykrywalny.
- C3. Progowy / wieloosobowy podpis release — nikt sam (łącznie z Tobą) nie wypuści update'u. Rozpuszcza
  „pojedynczy punkt". To realny powód, dla którego bus-factor popycha do małej fundacji / wielu
  sygnatariuszy — nie „pracy dla kogoś", tylko governance podpisu i ciągłości.
- C4. Warrant canary + świadomy wybór jurysdykcji (PL/UE vs US/NSL).

## D. Kolejność działań

Przed audytem (najpierw doc↔kod — na docs audytor buduje mental model):
1. Popraw sekcję replay w kyberbox.md (A1).
2. Wróć Cargo.lock + dodaj rust-toolchain pin (A2, A6) — fundament reproducible build (C1).
3. LICENSE (decyzja wg B6) + SECURITY.md (A3, A4).
4. Skonsolidowana sekcja FS/PCS + uzgodnij README (A5).

Pod plan z biblioteką:
5. Wydziel lithium_core jako samodzielny crate z czystym publicznym API (zdejmij sprzężenie z appką:
   contract/ i labels app-specyficzne, część error/db).
6. Domknij historię kombinatora (B3) — centralny deliverable audytu.
7. Zakres audytu = biblioteka (B4).
8. Obuduj ofertą integracji PQ (B5).
