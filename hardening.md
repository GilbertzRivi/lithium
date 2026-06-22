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

### B3. Cover traffic (daemon)

**Status:** zrobione (`lithiumd/src/traffic.rs`).

**Realizacja.** Stałokadencyjny scheduler: send dispatcher (jedna emisja `MsgSend` na tick — realny
send z kolejki albo dummy do cover-skrzynki) i fetch dispatcher (jeden `MsgFetch` na tick, round-robin
po {kontakty × okno generacji inbound} ∪ {cover-skrzynka}). Threat model = serwer (lokalny pasywny),
szum tylko gdy online. Cover-skrzynka (self-loop, etykieta `lithium/mbox/cover/v1`, derive z DEK,
rotacja dobowa) dostaje dummy-sendy i jest drenowana fetchem, więc serwer nie odróżnia jej od realnej
konwersacji. Realny ruch jedzie po tej samej kadencji: `contact_send` zawsze enqueue (zero feature-flagu,
zero direct-send), a manual fetch został usunięty na rzecz constant-rate pollingu (patrz zmiana trust
modelu w `docs/security-model.md`). Rozmiary równa istniejący padding transportu (bloki 32–64 KB).

**Granice (zapisane, by nie było teatru):** throughput realnych sendów capowany stopą (jeden slot/tick);
latencja odbioru rośnie z liczbą skrzynek w rotacji × interwał fetch; sam fakt online to metadana
(obrona vs serwer, nie vs globalny pasywny — 24/7 poza zakresem); cover-fetch z założenia odpytuje
też cover-skrzynkę co cykl.

**Plan (oryginalny).** Szum na poziomie daemona, by ukryć timing/wolumen realnego ruchu. **Constant-rate**, nie losowy/Poisson — burstowy ruch realny na wierzchu losowego szumu przecieka statystycznie.

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
- **Brak gwarancji dostarczenia / one-time fetch / constant-rate auto-fetch (zamiast manual fetch) / brak offline unlock / brak recovery** — non-goals z `docs/security-model.md`, nie do „naprawiania".

---

## Skrót kolejności

Wszystko przed audytem (audytor widzi finalny system):

1. **Redesign protokołu, na gotowych bibliotekach:** A1 OPAQUE + A2 anonimowy send + A3 usunięcie JWT — jako jeden redesign. W ramach A2 zarezerwuj slot PoW w wire-formacie.
2. **Contained (solo):** B2 fuzzing, B1 commit-reveal, B3 cover traffic, B4 opcjonalny guard.
3. **Artefakty:** C1 „co serwer widzi", C2 rama „audit as novel".

Po wdrożeniu (parametr operacyjny, nie zmiana protokołu): aktywuj PoW, jeśli TTL+IP okaże się za słabe na flood storage.
