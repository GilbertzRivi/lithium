# Lithium — roadmap

Kolejność, nie kalendarz (solo + praca full-time). Fazy 0-3 są sekwencyjne i zależne;
Faza 4 (prawne) biegnie równolegle od Fazy 1; Fazy 5-6 są post-audyt.
Szczegółowe uzasadnienia: patrz `tmp` (sekcje A/B/C/D).

## Teza

Nie sprzedajesz linii kodu — sprzedajesz **zaudytowaną poprawność + utrzymanie + transfer
odpowiedzialności + swoją ekspertyzę**. Aktywem jest atestacja, nie waga repo (małe = zaleta:
ciaśniejszy, tańszy, łatwiejszy do zaufania audyt).

Trwały rdzeń = **zarządzanie kluczami at-rest** (keyfile + crash-safe rotacja + rewrap + TPM,
~1100 linii) — uniwersalna potrzeba, trudna do wystandaryzowania.
KyberBox = drugi filar „póki świeci" — ma datę ważności (X-Wing/FIPS może go wystandaryzować).
Okno jest teraz.

Niezależność = własny podmiot + konsulting, nie posada. Komunikator zostaje demem/portfolio liby.

---

## Faza 0 — Higiena przed audytem (doc↔kod + repo)  [mała, najwyższy zwrot]

Cel: repo wiarygodne, dokumentacja zgodna z kodem, licencja ustalona.

- [ ] A1: popraw sekcję replay w `docs/kyberbox.md` (kod ma ReplayWindow w session.rs — doc zaprzecza)
- [ ] A2: wróć `Cargo.lock` do repo (fundament reproducible build)
- [ ] A6: dodaj `rust-toolchain.toml` (pin MSRV); ujednolić `fuzz/Cargo.toml` na edition 2024
- [ ] A5: dodaj dokument „Gwarancje FS/PCS warstwy E2E"; uzgodnij twarde claimy w README
- [ ] A3: dodaj `LICENSE` (decyzja wg B6 — najpierw przemyśl model)
- [ ] A4: dodaj `SECURITY.md` + link do `docs/security-model.md`

Wyjście: zero rozjazdów doc↔kod; `cargo test` / `clippy -D warnings` / `fmt` czyste;
`Cargo.lock` + `rust-toolchain.toml` w repo; LICENSE + SECURITY.md obecne.

## Faza 1 — Wydzielenie biblioteki  [średnia]

Cel: `lithium_core` jako samodzielny, czysty crate z publicznym API.

- [ ] Zdefiniuj dwa filary publicznego API: (1) at-rest key management, (2) hybrid encryption
- [ ] Odetnij sprzężenie z appką (`contract/`, app-specyficzne `labels`, część `error`/`db`)
- [ ] README biblioteki + przykłady użycia; semver `0.1`
- [ ] Komunikator konsumuje wydzielony crate jako zależność (dowód, że API stoi samo)

Wyjście: `lithium_core` buduje się i testuje samodzielnie; publiczne API zamrożone do audytu.

## Faza 2 — Przygotowanie do audytu (zakres = biblioteka)  [średnia]

Cel: gotowość do oddania ciasnej powierzchni audytorowi.

- [ ] B3: dokument „combiner story" — uzasadnienie kombinatora vs X-Wing; otwarte pytania
      z kyberbox.md jako wprost zadane pytania do audytora (to centralny deliverable)
- [ ] C1: pipeline reproducible build (lock + toolchain + kontener buildowy) jako artefakt „to audytowaliśmy"
- [ ] Threat model biblioteki (węższy niż messengera)
- [ ] Wybór audytora + budżet; rozważ grant na sam audyt (OTF / NLnet)

Wyjście: scope doc + reproducible build + lista pytań do audytora gotowe; audytor wybrany.

## Faza 3 — Audyt  [zależne od audytora]

Cel: niezależna atestacja poprawności hybrydy + key management.

- [ ] Przejście audytu
- [ ] Remediacja ustaleń
- [ ] Publikacja raportu (lub streszczenia) — dla tego segmentu jawny raport jest częścią produktu

Wyjście: raport + naprawione ustalenia + publiczny commit „post-audit".

## Faza 4 — Podstawa prawna i finansowa  [równolegle od Fazy 1]

Cel: struktura, która pozwala sprzedawać i zachować niezależność.

- [ ] B6: finalna licencja (source-available + komercja / dual) — przed publikacją pod LICENSE
- [ ] Spółka (sp. z o.o.) — przed pierwszym kontraktem / sprzedażą
- [ ] C4: decyzja jurysdykcji (PL/UE vs US/NSL); warrant canary
- [ ] Opcjonalnie: wniosek grantowy (NLnet/OTF) na audyt/utrzymanie — `docs/` to 80% wniosku

Wyjście: podmiot + licencja ustalone; (opcjonalnie) wniosek grantowy złożony.

## Faza 5 — Hardening dystrybucji  [post-audit, pre-commercial]

Cel: zamknięcie flanki „a jeśli zmuszą Ciebie" po stronie klienta (TCB = build + podpis).

- [ ] C2: binary transparency log (Sigstore / CT-style) — zmuszony update staje się wykrywalny
- [ ] C3: progowy / wieloosobowy podpis release — nikt sam (łącznie z Tobą) nie wypuści update'u;
      to wiąże się z governance i planem ciągłości

Wyjście: każdy release reprodukowalny + publicznie logowany + podpisany wieloma kluczami.

## Faza 6 — Go-to-market  [niezależny przychód]

Cel: pierwszy płatny kontrakt.

- [ ] B1/B2: pozycjonowanie „audited correct-by-construction hybrid"; lewar BSI/ANSSI (UE zaleca hybrydę)
- [ ] B5: oferta = licencja komercyjna + integracja/support PQ (główny przychód, na Twoich warunkach)
- [ ] Targetuj zamożny ogon: duże NGO/redakcje/kancelarie + firmy migrujące na PQ pod mandat
- [ ] Materiał sprzedażowy: raport z audytu + reproducible build jako dowód; otwieraj pitch
      właściwością „nakaz na operatora zwraca zero treści"

Wyjście: pierwszy płatny kontrakt integracyjny / licencyjny.

---

## Kamienie milowe

1. Repo czyste i spójne (Faza 0)
2. Biblioteka stoi sama (Faza 1)
3. Zaudytowana biblioteka z jawnym raportem (Fazy 2-3)
4. Podmiot + licencja + reprodukowalna, logowana dystrybucja (Fazy 4-5)
5. Pierwszy przychód (Faza 6)

## Krytyczna ścieżka

A2/A6 (Faza 0) → C1 reproducible build (Faza 2) → C2/C3 (Faza 5): pin zależności i toolchaina
to fundament całej odpowiedzi „a jeśli zmuszą Ciebie". Te pozornie kosmetyczne punkty są nośne.
