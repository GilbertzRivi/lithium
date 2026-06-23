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

## Workstream C — audit-readiness (PRZED AUDYTEM)

### C1. Artefakt „co serwer widzi per request"

**Status:** zrobione. Treść w `docs/security-model.md`, sekcja „Co serwer widzi per request".

Konkretny dokument dla audytora/fundatora — pokazuje, że metadane są przemyślane, nie zamiecione. Workstream A jest już wdrożony (OPAQUE, padding, PoW, one-time fetch), więc dokument opisuje stan realny, nie docelowy. Tabela per-endpoint (shake, register, login, msg/send, msg/fetch, revoke, delete) plus uczciwe zastrzeżenia: handler widoczny przejściowo przy register/login (nigdy surowo składowany, nigdy hasła), klucze podpisujące `msg/send` efemeryczne (nadawca nie identity-bound), IP/czas nieodłączne dla HTTP (mitygacja Tor/VPN to non-goal).

### C2. Rama „audit as novel construction"

**Status:** zrobione. Treść w `docs/security-model.md`, sekcja „Audyt jako nowa konstrukcja".

Krótka nota uzasadniająca: autorski KyberBox (KEM-DEM hybryda) i transport Shake/Session są bespoke z powodów historycznych, nie z principled wyboru; prośba o analizę jako nowych konstrukcji. Tabela prymitywów + wersje (aktualne/załatane). Granica zakresu: kod C PQClean (FFI) jest niezaudytowaną zależnością zewnętrzną.

---

## Zaakceptowane rezydua / non-goals (zapisane, by nie re-litygować)

- **Anonimowość IP** — spychana na użytkownika (Tor/VPN), jak w Signalu. GUI instruuje, by handle był nielinkowalny (nie nick/imię/email). Opaque handle robi pseudonim *nieidentyfikującym*, nie *niestałym* (`id_enc` jest deterministyczny → stabilny pseudonim narasta w czasie; jedno złe IP retroaktywnie podpina historię).
- **Login identity-bound** — patrz A3. Cena designu „serwer + hasło do odszyfrowania", nie bug.
- **Sparowany kontakt może cię zalać** — to ktoś OOB-zweryfikowany; obrona to `contact_forget`. Inherentne.
- **Brak gwarancji dostarczenia / one-time fetch / constant-rate auto-fetch (zamiast manual fetch) / brak offline unlock / brak recovery** — non-goals z `docs/security-model.md`, nie do „naprawiania".
