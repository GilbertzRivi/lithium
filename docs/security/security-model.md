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

### Constant-rate auto-fetch (cover traffic)

Daemon wysyła i pobiera ze stałą kadencją (`lithiumd/src/traffic.rs`): jedna emisja send i jeden
fetch na tick, niezależnie od realnej aktywności. Realne wiadomości jadą w slotach tej samej
kadencji, a puste sloty wypełnia dummy do własnej cover-skrzynki (self-loop), którą daemon sam
drenuje fetchem — dzięki temu serwer (lokalny pasywny adwersarz) nie odróżnia *kiedy* ani *ile*
realnie wysyłasz, ani które skrzynki są realnymi konwersacjami. Manual fetch został usunięty:
stale-kadencyjny polling jest jedyną ścieżką, bo burstowy realny ruch na wierzchu szumu przeciekałby
timingiem.

Granice: throughput realnych sendów jest capowany stopą (jeden slot na tick), a latencja odbioru
rośnie z liczbą skrzynek w rotacji (kontakty × okno generacji) razy interwał fetch. Sam fakt bycia
online pozostaje metadaną — obrona dotyczy serwera, nie globalnego pasywnego adwersarza (ruch 24/7
poza zakresem).

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

## Co serwer widzi per request

Każde żądanie jest szyfrowane KyberBoxem (X25519 + ML-KEM-1024, AEAD AES-256-GCM-SIV) i dopełniane
do losowego bloku (32-64 KB dla ciała, ósma część tego dla nagłówków) zanim w ogóle dotrze do
logiki serwera. Serwer dopełnienie zdejmuje dopiero po deszyfrze. Sam TLS terminuje reverse proxy
przed `lithiums`. Z tego wynika, że serwer nie zna ani treści, ani realnego rozmiaru plaintextu.
Poniższa tabela mówi, co serwer widzi naprawdę.

| Endpoint | Tryb / Auth | Co serwer widzi | Czego nie widzi |
|---|---|---|---|
| `shake` | Shake / klucze w nagłówkach | jednorazowy handshake, efemeryczne klucze publiczne | tożsamości, treści |
| `register_start/finish` | Session / klucze w nagłówkach | handler (przejściowo), wiadomości OPAQUE, zaszyfrowany DEK klienta | hasła, treści |
| `login_start/finish` | Session / handler | handler, przebieg OPAQUE; zwraca zaszyfrowany DEK | hasła, treści |
| `msg/send` | Session / klucze w nagłówkach + PoW | adres skrzynki (16/32 B, pseudolosowy), dopełniony blob treści, nonce PoW | nadawcy, odbiorcy, treści |
| `msg/fetch` | Session / klucze w nagłówkach | adres skrzynki | kto czyta, treści |
| `revoke` | Session / klucze w nagłówkach | remote-delete capability | tożsamości właściciela |
| `delete` | Session / JWT | token sesji wskazujący konto | hasła, treści |

Handler jest widoczny przejściowo tylko przy register i login, bo jest potrzebny jako identyfikator
poświadczenia OPAQUE i do wyliczenia `id_enc`. Nigdy nie jest składowany w postaci surowej i nigdy
nie towarzyszy mu hasło. Jedyne, co z tego wycieka, to egzystencja danego nicka, nie jego treść ani
powiązanie z aktywnością. Mechanikę składowania opisuje sekcja „Deterministyczne szyfrowanie
identyfikatora użytkownika na serwerze".

Klucze podpisujące żądanie `msg/send` są efemeryczne, generowane per request, więc serwer nie wiąże
nadawcy z jego tożsamością. Adres skrzynki jest pseudolosowy i nielinkowalny do konta — serwer
trasuje po skrzynce, nie po tożsamości.

IP i czas żądania są nieodłączne dla każdego połączenia HTTP, bo wynikają z warstwy TCP, nie z
protokołu Lithium. Ich ukrycie jest spychane na użytkownika (Tor, VPN) i pozostaje świadomym
non-goalem.

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

### Model autoryzacji IPC

Gniazdo jest tworzone z uprawnieniami `0600`, a na Linuksie peer jest identyfikowany przez
`SO_PEERCRED` — granicą jest ten sam UID. Komendy chronione wymagają tokenu sesji wydawanego przez
`unlock_keystore` i (na Linuksie) związanego z UID+PID połączenia, które go otrzymało. Token jest
unieważniany przez `lock_keystore` i `wipe_local`.

Bez tokenu działają tylko komendy, które z natury go nie potrzebują:

* `ping`,
* `unlock_keystore` — sama wydaje token,
* `remote_delete` — capability jest tu sekretem uwierzytelniającym i musi działać bez odblokowanego
  keystore (skasowanie konta na serwerze, gdy lokalnie nie da się już odblokować).

`set_server_url` i `set_server_identity` są konfiguracją bootstrapu: `unlock_keystore` odmawia startu,
dopóki URL nie jest ustawiony, a token istnieje dopiero po odblokowaniu — więc na first-run nie mogą
być bramkowane tokenem. Są więc dozwolone bez tokenu **wyłącznie dopóki nie istnieje aktywna sesja**;
gdy sesja jest aktywna, wymagają tokenu jak wszystko inne. Dzięki temu proces tego samego UID, który
nie odblokował keystore (nie ma tokenu), nie może po cichu przekierować klienta na inny serwer ani
podmienić przypiętej tożsamości serwera na żywej sesji. Legalny klient i tak dołącza token do
każdego żądania po odblokowaniu, więc zmiana jest dla niego przezroczysta.

## Logowanie i obserwowalność

Lithium loguje minimalnie i **nie loguje materiału wrażliwego**. W całej bazie nie ma logowania plaintextu wiadomości, handlerów, haseł, DEK-a ani kluczy, adresów skrzynek czy `contact_id`.

Co faktycznie trafia na wyjście:

* `lithiumd`: `eprintln!("fatal: {e}")` przy błędzie krytycznym startu (kod błędu, bez sekretów).
* `lithiumg`: komunikaty o ładowaniu czcionki emoji (`eprintln!`).
* `lithiums`: `tracing::info` jednorazowo przy pierwszym uruchomieniu (`wrote server.identity to {path}`) oraz `tracing::error` z zadań w tle (`mk_rotator`, `msg_reaper`) przy ich niepowodzeniu — komunikat błędu, bez danych użytkownika.

Serwer **nie prowadzi** strukturalnego logu żądań ani access logu, nie ma telemetrii ani „phone-home". Adresy skrzynek widoczne dla serwera nie są logowane.

**Zastrzeżenie operacyjne:** odwrotny proxy przed `lithiums` (terminujący TLS) może we własnym zakresie logować adresy IP klientów i znaczniki czasu — to jest poza kontrolą aplikacji i zależy od konfiguracji operatora. Guard anty-flood (`pre-replay`) kluczuje po `remote_addr` połączenia; konsekwencje pracy za proxy opisuje [deploy-instructions.md](../operations/deploy-instructions.md).

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
* constant-rate auto-fetch (polling) zamiast manual fetch,
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

Daemon buforuje `ServerBootstrap` (klucze publiczne serwera wczytane z lokalnego `server.identity`)
na czas życia procesu (`ProtocolManager::bootstrap_cache`). Jeśli operator zmieni `server.identity`
na serwerze — np. po re-key po kompromitacji — klient musi ręcznie zdobyć nowy plik (kanałem OOB)
i wgrać go komendą IPC `set_server_identity`, która natychmiast invaliduje cache
(`proto.invalidate_bootstrap_cache()`) — nowa tożsamość obowiązuje od następnego żądania,
bez potrzeby `lock_keystore`/`unlock_keystore`.

Kluczowa właściwość nie zależy od mechaniki cache'u, tylko od konstrukcji kryptograficznej: dopóki
klient nie wgra nowej tożsamości, każda próba komunikacji ze zrotowanym serwerem kończy się twardym
błędem, nie cichą degradacją. Klient szyfruje `Shake` do `shake_pub_x/k` ze starego pliku — serwer,
deszyfrujący prawdziwym (już zrotowanym) kluczem prywatnym, dostaje inny shared secret i AEAD
odrzuca żądanie. Nawet gdyby request jakimś cudem przeszedł, podpis odpowiedzi serwera jest
weryfikowany pod starymi `server_sig_ed/dili` — przy podpisie nowymi kluczami weryfikacja zawodzi
(`server_signature_invalid`). Nie istnieje retry, fallback ani automatyczne pobranie nowej tożsamości
z serwera — klient po prostu nie może rozmawiać z serwerem, dopóki operator nie dystrybuuje nowego
pliku OOB i użytkownik nie wgra go ręcznie.

Jest to celowa decyzja. Operator nie ma dostępu do urządzeń klientów i nie może wymusić
aktualizacji zaufania bez ich wiedzy i świadomej akcji. Automatyczna aktualizacja kluczy serwera
otworzyłaby wektor dla operatora, który chce podmienić klucze bez wiedzy użytkownika.

To dotyczy nie tylko re-key po kompromitacji, ale `server.identity` w ogóle: protokół nie definiuje
żadnego adresu URL ani endpointu, z którego dałoby się ten plik pobrać automatycznie — ani przy
pierwszym uruchomieniu, ani przy odświeżeniu. Taki endpoint nigdy nie istniał i nie jest planowany.
Jedyna droga to kanał out-of-band i ręczne wgranie pliku komendą `set_server_identity` — zawsze,
bez wyjątków.

Twardość tej blokady (komunikacja zrywa się całkowicie, nie degraduje się) jest funkcją
bezpieczeństwa, nie wadą UX.

## Audyt jako nowa konstrukcja

Część protokołu Lithium jest autorska i należy ją analizować jak nową konstrukcję kryptograficzną,
nie jak złożenie znanych, zrecenzowanych bloków:

* KyberBox, hybryda KEM-DEM (`lithium_core/src/crypto/kyberbox.rs`),
* transport Shake i Session (`lithiums/src/transport/mod.rs`),
* warstwa E2E WireV1 z ratchetem (`lithiumd/src/e2e/`).

Te części są bespoke z powodów historycznych, nie z principled wyboru. Protokół wyrósł organicznie
(Python + RSA przeszedł na konstrukcję postkwantową) i nie ma dla niego uczciwego uzasadnienia
„własne zamiast standardu". Właściwa rama wobec audytora jest prosta: to autorska konstrukcja
hybrydowa, proszę przeanalizować ją jako nową.

Nowe elementy protokołu są celowo wpięciami zrecenzowanych standardów, nie hand-rollem:

* OPAQUE przez bibliotekę `opaque-ke 4.0.1` (draft-irtf-cfrg-opaque),
* PoW = hashcash (`lithium_core/src/pow.rs`).

Tam audyt jest przeglądem integracji (jak standard został wpięty), nie przeglądem konstrukcji.
Hand-roll OPAQUE odtworzyłby dokładnie ten problem bespoke surface, którego te wpięcia unikają.

Prymitywy i ich wersje (aktualne, załatane):

| Warstwa | Prymityw | Implementacja |
|---|---|---|
| Szyfrowanie klasyczne | X25519 | x25519-dalek 2.0.1 |
| Szyfrowanie PQ | ML-KEM-1024 | pqcrypto 0.18.1 (FFI do C PQClean) |
| AEAD | AES-256-GCM-SIV | aes-gcm-siv 0.11.1 |
| Podpis klasyczny | Ed25519 | ed25519-dalek 2.2.0 |
| Podpis PQ | ML-DSA-87 | pqcrypto 0.18.1 (FFI do C PQClean) |
| KDF | HKDF-SHA256 | hkdf 0.12 |
| Hasła | Argon2 | argon2 0.5.3 |
| PAKE | OPAQUE (ristretto255 + argon2) | opaque-ke 4.0.1 |

Granica zakresu: kod C z PQClean, używany przez FFI w `pqcrypto`, jest niezaudytowaną zależnością
zewnętrzną i pozostaje poza zakresem przeglądu konstrukcji Lithium.

## Podsumowanie

Lithium nie ma być wygodne. Ma być trudne do zdradzenia.

Jeżeli jakaś cecha zwiększa recoverability, wygodę albo klasyczny komfort użytkownika kosztem
większego zaufania do operatora, większej ilości metadanych albo większej odzyskiwalności danych po kompromitacji,
to taka cecha nie jest domyślnie zaletą.

W Lithium bardzo często jest odwrotnie.

To nie jest błąd projektu. To jest projekt.