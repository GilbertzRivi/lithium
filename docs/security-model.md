# Lithium — model bezpieczeństwa i założenia projektowe

## Cel projektu

Lithium nie jest komunikatorem konsumenckim.

To komunikator projektowany dla środowisk, w których serwer, operator, infrastruktura, storage i lokalne środowisko
wykonawcze mogą być częściowo albo całkowicie niegodne zaufania.

Priorytetem projektu nie jest wygoda. Priorytetem jest ograniczenie zaufania.

## Priorytety

Priorytety Lithium są następujące:

1. poufność treści,
2. ograniczenie zaufania do operatora i serwera,
3. minimalizacja metadanych,
4. ograniczenie retencji,
5. utrudnienie późniejszego odzyskania danych,
6. dopiero na końcu wygoda i klasyczna niezawodność komunikatora.

Jeżeli wygoda koliduje z prywatnością lub trust model, prywatność wygrywa.

## Model zaufania

Lithium zakłada, że:

* serwer może być złośliwy, przejęty, monitorowany albo prawnie zmuszony do współpracy,
* operator nie może być traktowany jako podmiot zaufany dla poufności danych,
* storage klienta może zostać przejęty,
* pamięć operacyjna może zostać przejęta lub zdumpowana,
* lokalne środowisko klienta nie jest domyślnie bezpieczne,
* kanał out-of-band używany do bootstrapu zaufania jest wymaganym elementem modelu bezpieczeństwa.

## Co Lithium ma zapewniać

Lithium ma dążyć do tego, aby:

* serwer nie znał treści wiadomości,
* serwer nie był źródłem zaufania między użytkownikami,
* operator matematycznie nie był w stanie ujawnić danych,
* kompromitacja serwera nie dawała dostępu do możliwie niczego,
* kompromitacja dysku nie umożliwiała odzyskania danych,
* utrata części stanu mogła skutkować utratą danych, jeżeli zmniejsza to ryzyko kompromitacji.

## Świadome kompromisy

Poniższe rzeczy nie są błędami. Są cechami wynikającymi z modelu projektu.

### Brak gwarancji dostarczenia

Lithium nie gwarantuje dostarczenia każdej wiadomości.

### Ograniczona retencja

Wiadomości są efemeryczne i przechowywane na serwerze tylko przez ograniczony czas.

### One-time fetch

Wiadomości są projektowane jako one-time fetch i zostają usunięte po pobraniu.

### Manual fetch

Manual fetch jest celowy. Ma ograniczać korelację, zmniejszać ekspozycję metadanych i nie upodabniać
systemu do klasycznego, stale aktywnego komunikatora.

### Brak pełnego offline unlock

Offline unlock nie jest celem projektu.

Odszyfrowanie lokalnych danych zależy częściowo od komponentu odzyskiwanego przez serwer,
to jest to świadoma decyzja. Preferowane jest utracenie możliwości odszyfrowania danych
zamiast pozostawienia ich odzyskiwalnymi po utracie kontroli nad urządzeniem.

### Recoverability przegrywa z bezpieczeństwem

Lithium w wielu miejscach preferuje nieodwracalną utratę dostępu nad wygodny odzysk.

To nie jest UX bug. To jest założenie.

### Deterministyczne szyfrowanie identyfikatora użytkownika na serwerze

Identyfikator użytkownika w bazie serwera jest derywowany deterministycznie z handlera (`UUID v5`)
i szyfrowany deterministycznie (nonce wyprowadzony z UUID i DEK).

Jest to świadomy trade-off wymagany przez semantykę lookup — bez deterministyczności serwer
musiałby przechowywać plaintext handlera lub dodatkową tablicę mapowań.

Konsekwencja: ten sam użytkownik zawsze daje ten sam `id_enc`. Ponieważ jednak w bazie istnieje
dokładnie jeden wiersz na użytkownika, powtórzenia w bazie nie są możliwe. Dwa snapshoty bazy
też nic nie ujawnią ponad fakt, że dany wiersz nadal istnieje — nie można z tego odtworzyć
handlera, bo jest zaszyfrowany i zahashowany.

Nie jest to podatność w modelu Lithium, ale jest to świadome odstępstwo od semantyki
niedeterministycznego szyfrowania.

### Lokalny resource exhaustion

Niektóre struktury in-memory rosną proporcjonalnie do liczby unikalnych wartości w żądaniach.
Przykład: `contact_fetch_locks` w `lithiumd` — mapa rośnie wraz z liczbą unikalnych `contact_id`,
nigdy nie jest czyszczona.

Przy normalnym użyciu to kilkadziesiąt wpisów i jest nieistotne.
Przy intencjonalnym zalewaniu losowymi identyfikatorami mapa rośnie w nieskończoność.

Jest to świadoma decyzja. Lithium nie jest komunikatorem dla anonimowych, niezaufanych klientów.
Strona, która ma dostęp do mailboxa, jest stroną uwierzytelnioną — a ktoś, kto celowo wyczerpuje
własne zasoby, robi krzywdę sobie. Bounded resource exhaustion przez niezaufane requestujące strony
nie jest zagrożeniem w modelu Lithium, bo nie narusza poufności ani integralności danych.

## Serwer

Serwer jest z definicji niezaufany dla poufności.

Serwer może:

* odmawiać działania,
* gubić dane,
* usuwać dane,
* wpływać na dostępność,
* próbować korelować zachowania użytkowników.

Serwer nie powinien móc:

* odszyfrować treści,
* ustanawiać zaufania między peerami,
* uczestniczyć w parowaniu użytkowników.

## Lokalny klient i IPC

Lokalny daemon i IPC są granicą uprzywilejowaną.

To jest jedna z najważniejszych granic bezpieczeństwa w całym systemie, ponieważ daemon ma dostęp do:

* plaintextu,
* odblokowanego stanu kryptograficznego,
* operacji destrukcyjnych,
* operacji administracyjnych,
* operacji na tożsamości i stanie lokalnym.

W praktyce oznacza to, że naruszenie IPC albo lokalnego modelu uprawnień może omijać znaczną część zabezpieczeń sieciowych.

Dlatego problemy dotyczące IPC, lokalnej autoryzacji, uprawnień i modelu stanu są realnymi problemami bezpieczeństwa.

## Operacje destrukcyjne

Lithium przyjmuje asymetrię:

* odszyfrowanie ma być trudniejsze,
* zniszczenie lokalnego stanu może być łatwiejsze.

Brak sekretu prowadzi do utraty danych.
Brak sekretu nie może prowadzić do odzyskania danych.

Wipe local jest operacją destrukcyjną. Nie jest recovery.

## Co powinno być audytowane jako realny problem

Realnymi problemami są rzeczy, które łamią założenia Lithium, w szczególności:

* obejście modelu tożsamości,
* MITM lub podstawienie peera mimo modelu OOB,
* naruszenie granicy IPC i lokalnego daemona,
* błędy crash consistency i rotacji kluczy,
* cicha utrata integralności lub kluczy,
* błędy powodujące niejawne nadpisanie stanu kryptograficznego,
* błędy ujawniające plaintext lub wrażliwy materiał kluczowy poza założonym modelem,
* błędy, które psują jawnie deklarowane gwarancje bezpieczeństwa.

## Czego nie należy raportować jako podatności bez kontekstu

Poniższe rzeczy nie powinny być automatycznie klasyfikowane jako podatności bez odniesienia do threat model i non-goals:

* brak gwarancji dostarczenia,
* manual fetch,
* one-time fetch + delete,
* ograniczona retencja,
* brak offline unlock,
* brak recovery przez operatora,
* możliwość utraty danych po utracie komponentu serwerowego,
* preferowanie destrukcji lokalnego stanu nad jego odzysk,
* resource exhaustion wywołany przez uwierzytelnioną stronę na własnym endpoincie (lokalny DoS).

## Klasyfikacja ustaleń audytowych

Każde ustalenie powinno być klasyfikowane jako jedno z poniższych:

1. **podatność** — łamie założenia bezpieczeństwa Lithium,
2. **trade-off** — jest zgodne z modelem, ale kosztowne operacyjnie lub UX-owo,
3. **non-goal** — dotyczy czegoś, czego Lithium celowo nie zapewnia.

Brak tego rozróżnienia prowadzi do błędnej oceny systemu.

## Zmiana server.identity jest celowo bolesna

Daemon buforuje `ServerBootstrap` (klucze publiczne serwera) przez cały czas trwania sesji keystore.
Jeśli operator zmieni `server.identity` na serwerze — np. po re-key po kompromitacji —
każdy klient musi ręcznie wgrać nowy plik i wykonać `lock_keystore` + `unlock_keystore`.

Jest to celowa decyzja. Operator nie ma dostępu do urządzeń klientów i nie może wymusić
aktualizacji zaufania bez ich wiedzy i świadomej akcji. Automatyczna aktualizacja kluczy serwera
otworzyłaby wektor dla operatora, który chce podmienić klucze bez wiedzy użytkownika.

Bolesność tej operacji jest funkcją bezpieczeństwa, nie wadą UX.

## Podsumowanie

Lithium nie ma być wygodne. Ma być trudne do zdradzenia.

Jeżeli jakaś cecha zwiększa recoverability, wygodę albo klasyczny komfort użytkownika kosztem
większego zaufania do operatora, większej ilości metadanych albo większej odzyskiwalności danych po kompromitacji,
to taka cecha nie jest domyślnie zaletą.

W Lithium bardzo często jest odwrotnie.

To nie jest błąd projektu. To jest projekt.