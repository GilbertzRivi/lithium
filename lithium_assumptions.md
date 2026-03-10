# Lithium — założenia projektowe i bezpieczeństwa

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
* operator matematycznie nie był w stanie ujawnić danych.
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

## Non-goals

Lithium celowo nie próbuje zapewnić:

* recovery po utracie sekretów,
* działania offline,
* gwarancji dostarczenia każdej wiadomości,
* wygodnego UX znanego z komunikatorów masowych,
* odzyskiwania danych,
* ochrony przed całkowicie przejętym endpointem,
* funkcji zwiększających wiedzę serwera tylko po to, żeby system był przyjemniejszy w użyciu.

Brak tych właściwości nie powinien być klasyfikowany jako podatność, jeśli wynika z modelu bezpieczeństwa.

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
* uczestniczyć w parowaniu użytkowników

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
* preferowanie destrukcji lokalnego stanu nad jego odzysk.

## Klasyfikacja ustaleń audytowych

Każde ustalenie powinno być klasyfikowane jako jedno z poniższych:

1. **podatność** — łamie założenia bezpieczeństwa Lithium,
2. **trade-off** — jest zgodne z modelem, ale kosztowne operacyjnie lub UX-owo,
3. **non-goal** — dotyczy czegoś, czego Lithium celowo nie zapewnia.

Brak tego rozróżnienia prowadzi do błędnej oceny systemu.

## Podsumowanie

Lithium nie ma być wygodne. Ma być trudne do zdradzenia.

Jeżeli jakaś cecha zwiększa recoverability, wygodę albo klasyczny komfort użytkownika kosztem
większego zaufania do operatora, większej ilości metadanych albo większej odzyskiwalności danych po kompromitacji,
to taka cecha nie jest domyślnie zaletą.

W Lithium bardzo często jest odwrotnie.

To nie jest błąd projektu. To jest projekt.
