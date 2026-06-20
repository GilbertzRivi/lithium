# Lithium — plan hardeningu

> Status: plan roboczy. Zakres = ustalenia z sesji projektowej, nie pełny audyt.
> Dokument jest sekwencjonowany **wokół audytu zewnętrznego** — patrz zasada nadrzędna.

## Zasada nadrzędna (sekwencjonowanie)

Głównym ryzykiem projektu nie jest błąd w prymitywach (te są dobrane poprawnie), lecz **powierzchnia autorskiego protokołu**: każdy bespoke kawałek audytor musi analizować od zera.

Z tego wynika kolejność prac:

1. **Przed audytem rób rzeczy contained** — nie zmieniają konstrukcji kryptograficznej protokołu: fuzzing, commit-reveal w parowaniu, cover traffic, utwardzenie niezmienników, artefakty audit-readiness.
2. **Zmiany protokołu (Workstream A) zrób PRZED audytem.** Audyt jest drogi — audytor ma recenzować *finalny* design, nie wersję, którą i tak zmienisz po nim (audytowanie stanu, który zaraz wyrzucisz, to spalony budżet). To też prawda inżynierska: każda zmiana protokołu jest po wdrożeniu na produkcję dużo droższa i ryzykowniejsza, więc wszystko, co kształtuje protokół, robi się przed produkcją.
3. **Warunek, który to umożliwia: nowe części protokołu = recenzowane implementacje standardów, nie hand-roll.** OPAQUE (draft-irtf-cfrg-opaque, CFRG) z gotowej, sprawdzonej biblioteki; PoW = hashcash. Wtedy audytor robi *przegląd integracji* (jak wpięłaś znany protokół), nie *przegląd konstrukcji* (nowa krypto) — taniej i bezpieczniej. Hand-roll OPAQUE odtworzyłby problem bespoke surface. Audyt skupia się wtedy na tym, co naprawdę autorskie: istniejący KyberBox i transport Shake/Session.

Nie ma „principled why custom vs standard" dla istniejącego protokołu — wyrósł organicznie (Python+RSA → PQ). Uczciwa rama wobec audytora: *„to jest autorska konstrukcja hybrydowa, przeanalizujcie ją jako nową"*, nie udawane uzasadnienie.

---

## Workstream B — rzeczy contained (PRZED AUDYTEM, solo)

### B1. Commit-reveal w parowaniu

**Status:** otwarte. SAS dziś = 12 symboli / 72 b (`lithiumd/src/commands/contact_verify_emoji.rs:25`).

**Problem.** Wymiana `lci1:` nie ma commitmentu kluczy — to surowe klucze publiczne. Atakujący kontrolujący kanał OOB może grindować własny zestaw offline, by dopasować SAS. Obecna obrona to *wyłącznie długość* (72 b czyni grind niewykonalnym), nie struktura.

**Plan.** Dodać commitment: strona A wysyła `H(klucze)` OOB **przed** ujawnieniem, B ujawnia, A ujawnia. Grind offline znika strukturalnie (atakujący musi commitować przed poznaniem celu → SAS staje się one-shot 2^-N). Pozwala docelowo skrócić SAS.

**Pliki.** `lithiumd/src/commands/invite_create.rs`, `invite_accept.rs`, stan kontaktu, onboarding w `lithiumg`.

### B2. Fuzzing

**Status:** otwarte.

**Dlaczego.** Złożoność jest w warstwie stanowej E2E (bootstrap/ratchet/prekey-recover + okna generacji mailboxa + wycofywanie bootstrapu) i w parserach. To miejsca, gdzie chowają się bugi, które audytor i tak znajdzie — taniej fuzzerem przed zegarem.

**Cele fuzzingu:**
- Parsery (wejścia z sieci / od peera): `lithiumd/src/e2e/wire.rs` (`unpack_wire`), `lithiumd/src/commands/invite_codec.rs`, `lithium_core/src/keys/keyfile.rs`, `lithium_core/src/contract/identity_file.rs`, `lithium_core/src/crypto/kyberbox.rs` (`decrypt`).
- Maszyna stanów E2E: sekwencje `encrypt_for_peer`/`decrypt_for_us`/`decrypt_for_prekey` z losowymi przeplotami i powtórkami (`lithiumd/src/e2e/session.rs`, `state_self.rs`, `state_peer.rs`) — niezmiennik: brak paniki, brak wycieku plaintextu bez podpisu, monotoniczność seq/gen.

### B3. Cover traffic (daemon)

**Status:** otwarte (nie istnieje).

**Plan.** Szum na poziomie daemona, by ukryć timing/wolumen realnego ruchu. **Constant-rate**, nie losowy/Poisson — burstowy ruch realny na wierzchu losowego szumu przecieka statystycznie.

**Granice (do zapisania, żeby nie było teatru):**
- Sam wzorzec online to metadana (kiedy daemon szumi = strefa czasowa / rytm dobowy). „Tylko IP-on" wymaga ruchu 24/7 → koszt pasma/baterii/serwera.
- Zdecydować threat model: obrona przed *serwerem* (lokalny pasywny) czy *globalnym pasywnym* adwersarzem — różne budżety ruchu.
- Większość „noise feature'ów" jest teatrem, bo stopa za niska, by zamaskować burst. Albo robić to porządnie (constant-rate), albo wcale.

**Pliki.** Nowy scheduler w `lithiumd` (np. obok `protocol_manager`); interakcja z reaperem/limit serwera.

### B4. Utwardzenie niezmiennika anti-replay

**Status:** w dużej części zrobione.

**Stan.** Replay łapie dedup `UNIQUE(msg_id)` w warstwie storage (`lithiumd/src/db/repo.rs::add_message`, `lithiumd/src/db/models.rs`), wsparte one-time fetch po stronie serwera. **Test pinujący niezmiennik istnieje.** `docs/kyberbox.md` opisuje to poprawnie (dedup w storage, nie seq w krypto).

**Pozostaje (opcjonalnie).** Jawny seen-seq guard w `lithiumd/src/e2e/session.rs` jako defense-in-depth. Przy zapiętym teście + `UNIQUE` to **nie jest must** — tylko gdyby chcieć, by ochrona istniała też niezależnie od warstwy DB.

---

## Workstream C — audit-readiness (PRZED AUDYTEM)

### C1. Artefakt „co serwer widzi per request"

Konkretny dokument dla audytora/fundatora — pokazuje, że metadane są przemyślane, nie zamiecione. Stan docelowy po Workstream A:

| Endpoint | Auth | Co serwer realnie widzi |
|---|---|---|
| `register` | KeysInHeaders | że powstało konto (`id_enc`), IP, czas; **nie** hasło (po OPAQUE) |
| `login` (OPAQUE) | OPAQUE | że *to* konto sięgnęło po swój DEK, IP, czas; **nie** hasło, **nie** treść |
| `msg/send` (po A2) | KeysInHeaders | adres skrzynki (pseudolosowy, nielinkowalny do tożsamości), rozmiar (paddowany), IP, czas; **nie** nadawcę, **nie** odbiorcę, **nie** treść |
| `msg/fetch` | KeysInHeaders | że ktoś czyta adres, IP, czas |

### C2. Rama „audit as novel construction"

Krótka nota uzasadniająca: autorski KyberBox (KEM-DEM hybryda) i transport Shake/Session są bespoke z powodów historycznych, nie z principled wyboru; prośba o analizę jako nowych konstrukcji. Lista prymitywów + wersje (są aktualne/załatane). Granica zakresu: kod C PQClean (FFI) jest niezaudytowaną zależnością zewnętrzną.

---

## Zaakceptowane rezydua / non-goals (zapisane, by nie re-litygować)

- **Anonimowość IP** — spychana na użytkownika (Tor/VPN), jak w Signalu. GUI instruuje, by handle był nielinkowalny (nie nick/imię/email). Opaque handle robi pseudonim *nieidentyfikującym*, nie *niestałym* (`id_enc` jest deterministyczny → stabilny pseudonim narasta w czasie; jedno złe IP retroaktywnie podpina historię).
- **Login identity-bound** — patrz A3. Cena designu „serwer + hasło do odszyfrowania", nie bug.
- **Sparowany kontakt może cię zalać** — to ktoś OOB-zweryfikowany; obrona to `contact_forget`. Inherentne.
- **Brak gwarancji dostarczenia / one-time fetch / manual fetch / brak offline unlock / brak recovery** — non-goals z `docs/security-model.md`, nie do „naprawiania".

---

## Skrót kolejności

Wszystko przed audytem (audytor widzi finalny system):

1. **Redesign protokołu, na gotowych bibliotekach:** A1 OPAQUE + A2 anonimowy send + A3 usunięcie JWT — jako jeden redesign. W ramach A2 zarezerwuj slot PoW w wire-formacie.
2. **Contained (solo):** B2 fuzzing, B1 commit-reveal, B3 cover traffic, B4 opcjonalny guard.
3. **Artefakty:** C1 „co serwer widzi", C2 rama „audit as novel".

Po wdrożeniu (parametr operacyjny, nie zmiana protokołu): aktywuj PoW, jeśli TTL+IP okaże się za słabe na flood storage.
