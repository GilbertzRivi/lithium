# Lithium — co to jest i dlaczego powstało

Lithium to komunikator do wysyłania wiadomości. Obsługuje się go tak samo jak każdy inny — piszesz, wysyłasz, druga osoba czyta. Interfejs jest prosty i nie robi wrażenia.

Wrażenie robi to, czego w nim nie ma i co dzieje się pod spodem.

---

## Zacznijmy od tego, jak działają inne komunikatory

Kiedy wysyłasz wiadomość przez telefon, ta wiadomość trafia na serwer firmy, która prowadzi komunikator — na przykład Meta, Google, Apple czy Telegram. Firma twierdzi, że jej nie czyta. Część z nich stosuje szyfrowanie, które sprawia, że jest to trudniejsze. Ale wszystkie mają jedną wspólną cechę: **ufasz firmie**.

Ufasz, że nie czyta. Ufasz, że nie sprzedaje danych reklamodawcom. Ufasz, że nie wykona nakazu sądowego i nie wyda twoich rozmów. Ufasz, że nie zostanie zhakowana. Ufasz, że nie zmieni regulaminu.

To nie jest paranoja — to jest normalny układ, który działa dla zdecydowanej większości zastosowań. Jeśli piszesz do znajomych co robisz w weekend, zaufanie do firmy jest wystarczające.

Ale są sytuacje, w których zaufanie do kogokolwiek poza rozmówcą jest za dużo.

---

## Co by musiało być prawdą, żeby komunikator był naprawdę prywatny

Żeby nikt poza rozmówcami nie mógł przeczytać rozmowy, trzeba spełnić jeden warunek: **klucze do odszyfrowania wiadomości nie mogą nigdy opuścić urządzeń rozmówców**.

Jeśli firma prowadząca serwer ma do nich dostęp — choćby pośredni, choćby tylko w teorii — to nie jest prawdziwa prywatność. To jest prywatność warunkowa: dopóki firma się zachowuje.

Lithium jest zbudowany tak, żeby warunek był spełniony bezwarunkowo. Serwer nie ma kluczy. Nigdy ich nie miał. Nie może ich uzyskać. To nie jest kwestia polityki — to kwestia architektury.

---

## Jak to działa w praktyce

Kiedy instalujesz Lithium na swoim urządzeniu, aplikacja generuje unikalny zestaw kluczy kryptograficznych. Są one losowe, specyficzne dla twojego urządzenia i nigdy nigdzie nie są wysyłane. Żaden serwer ich nie zna.

Kiedy piszesz wiadomość, jest ona szyfrowana na twoim urządzeniu — zanim w ogóle trafi do internetu. Serwer dostaje pakiet danych, który wygląda jak losowy ciąg bajtów. Bez klucza, który ma tylko odbiorca, ten ciąg bajtów jest bezużyteczny.

Serwer jest tu dosłownie listonoszem, który dostarcza zapieczętowaną kopertę. Widzi, że coś dostarczył. Nie widzi, co.

---

## Serwer jako potencjalny wróg

Większość systemów zakłada, że serwer jest po naszej stronie. Lithium zakłada coś odwrotnego: **serwer może być wrogi**.

Może być przejęty przez hakera. Może działać w jurysdykcji, która zmusi go do wydania danych. Może być prowadzony przez kogoś, kto ma własne interesy. Może być monitorowany bez wiedzy właściciela.

W każdym z tych scenariuszy Lithium zachowuje się tak samo: atakujący dostaje zaszyfrowane dane bez możliwości ich odczytania. Historia rozmów nie jest przechowywana na serwerze — wiadomości są usuwane natychmiast po odebraniu. Nie ma czego wydać. Nie ma czego ukraść.

Operatorzy serwera nie mogą odczytać wiadomości, bo nie mają kluczy.
Nie mogą ustalić, kto do kogo pisze, bo adresy skrzynek są matematycznie zaciemnione.
Nie mogą nawet wyszukać użytkownika po nazwie konta, bo nazwy kont nie są przechowywane w postaci czytelnej — serwer widzi tylko zaszyfrowane identyfikatory.

---

## Ochrona przed przyszłością: szyfrowanie post-kwantowe

Większość szyfrowania w internecie opiera się na trudności pewnych problemów matematycznych. Na przykład: żeby złamać typowy klucz szyfrujący, trzeba rozłożyć bardzo dużą liczbę na czynniki pierwsze — co zajmuje nawet najszybszym komputerom miliony lat.

Komputery kwantowe, nad którymi pracują między innymi rządy USA, Chin i duże korporacje, mogą rozwiązać te problemy w ciągu godzin lub minut. Kiedy to nastąpi — a w środowiskach kryptograficznych pytanie brzmi raczej *kiedy* niż *czy* — znaczna część dzisiejszego szyfrowania przestanie być bezpieczna.

Jest też bardziej natychmiastowy problem: służby wywiadowcze niektórych państw już teraz zbierają zaszyfrowany ruch sieciowy z założeniem, że odszyfrują go gdy komputery kwantowe będą dostępne. To strategia zwana "harvest now, decrypt later" — zbieraj teraz, odszyfruj później.

Lithium używa algorytmów szyfrowania zatwierdzonych przez NIST (Narodowy Instytut Standardów i Technologii USA) w 2024 roku jako odpornych na komputery kwantowe. Jednocześnie z algorytmami klasycznymi — co oznacza, że żeby złamać szyfrowanie, trzeba by złamać oba rodzaje jednocześnie. To zabezpieczenie zarówno przed obecnymi zagrożeniami, jak i przed tymi, które dopiero nadchodzą.

---

## Przeszłość jest bezpieczna nawet wtedy, gdy coś pójdzie nie tak

Przejęcie klucza i przejęcie urządzenia to dwie różne rzeczy. Urządzenie może zostać skradzione — ale klucze kryptograficzne mogą też wyciec inaczej: przez błąd w oprogramowaniu, przez atak na pamięć, przez lukę w systemie. To jest scenariusz, na który Lithium jest przygotowany niezależnie.

Wyobraź sobie, że ktoś zdobył twój aktualny klucz kryptograficzny. Co może zobaczyć?

W większości systemów — całą historię rozmów, wstecz do początku.

W Lithium — **wyłącznie wiadomości jeszcze nieodebrane w tej chwili**. Nic więcej.

Każda wiadomość jest szyfrowana świeżymi, jednorazowymi kluczami wygenerowanymi specjalnie dla niej — i tylko dla niej. Po odebraniu wiadomości klucze, którymi była zaszyfrowana, są trwale kasowane z obu urządzeń. Nie ma ich na dysku, nie ma ich w pamięci — zniknęły. Co więcej, klucze używane do szyfrowania regularnie rotują: co pewną liczbę wiadomości generowana jest zupełnie nowa para, a stara jest niszczona. Ten mechanizm — zwany *ratchetem* — sprawia, że nawet klucze z poprzedniego tygodnia nie istnieją już nigdzie.

Przejęcie klucza bieżącego nie daje dostępu do niczego, co zostało powiedziane wcześniej. Historia nie jest odtwarzalna, bo klucze potrzebne do jej odczytania dawno przestały istnieć.

To właściwość zwana *forward secrecy* — przyszłe naruszenie nie cofa się w czasie.

---

## Co się dzieje, gdy zgubisz telefon

To jest miejsce, w którym Lithium świadomie wybiera bezpieczeństwo kosztem wygody.

**Nie można odzyskać hasła.** Jeśli zapomnisz hasła do aplikacji, nie ma opcji "wyślij mi link na email" ani "potwierdź SMS-em". Gdyby takie opcje istniały, oznaczałoby to, że ktoś inny — firma, serwer, dostawca e-maila — mógłby wejść na twoje konto zamiast ciebie. Więc tych opcji nie ma.

**Nie można przenieść kont między urządzeniami.** Klucze są wygenerowane na jednym urządzeniu i na nim zostają. Nie ma mechanizmu synchronizacji z chmurą, bo chmura musiałaby znać klucze — a to zaprzeczałoby całemu modelowi bezpieczeństwa.

**Ale jest jedno awaryjne zabezpieczenie.** Przy rejestracji aplikacja generuje specjalny kod — jednorazowy token awaryjny. Jeśli zgubisz urządzenie, możesz użyć tego kodu z dowolnego innego miejsca i usunąć swoje konto z serwera.

Co to konkretnie znaczy: serwer usuwa klucz szyfrowania danych, który przechowywał w twoim imieniu. Ten klucz jest jednym z dwóch składników potrzebnych do odszyfrowania danych na skradzionym urządzeniu — bez niego zawartość lokalnej bazy staje się trwale niedostępna dla kogokolwiek, kto ma to urządzenie w rękach, nawet jeśli zna hasło.

Warto wiedzieć, że logowanie na skradzionym urządzeniu i tak jest już niemożliwe bez fizycznego dostępu — klucze potrzebne do uwierzytelnienia są na tym urządzeniu i nigdzie indziej. Token awaryjny działa więc nie dlatego, że "blokuje konto" w klasycznym sensie, ale dlatego, że kryptograficznie uniemożliwia odszyfrowanie danych przez osobę, która ma to urządzenie.

Kod do tego tokenu należy zapisać i przechowywać osobno od urządzenia. Serwer przechowuje tylko jego kryptograficzny odcisk (hash), nigdy wartość — więc nawet operator serwera nie może go użyć ani wykonać tej operacji za ciebie.

---

## Tożsamość serwera jest przypięta

Kiedy klient Lithium łączy się z serwerem, weryfikuje jego tożsamość na podstawie pliku `server.identity` — zestawu kluczy kryptograficznych, który administrator serwera dostarcza użytkownikom raz, przy konfiguracji.

Jeśli ktoś podmieni serwer, skieruje ruch na inną maszynę, przechwyci połączenie albo w jakikolwiek sposób zmieni klucze serwera — aplikacja odmówi połączenia. Nie ma negocjacji, nie ma "czy jesteś pewna?", nie ma możliwości zaakceptowania nowej tożsamości w tle.

Oznacza to, że podmiana serwera bez wiedzy użytkowników jest niemożliwa technicznie. Jedyną drogą do zmiany tożsamości serwera jest świadome wgranie nowego pliku przez każdego użytkownika z osobna.

---

## Dlaczego wiadomości nie przychodzą same

Żeby zobaczyć nowe wiadomości, trzeba kliknąć "pobierz". Aplikacja nie sprawdza sama w tle co kilka sekund.

To celowe. Automatyczne sprawdzanie oznaczałoby, że twoje urządzenie regularnie kontaktuje się z serwerem — i ktoś obserwujący ruch sieciowy mógłby śledzić wzorce aktywności: kiedy jesteś przy telefonie, jak często sprawdzasz wiadomości, w jakich godzinach. To metadane, które mówią więcej niż się wydaje.

Model "pobierz ręcznie" eliminuje te wzorce kosztem pewnej niedogodności.

---

## Dodawanie kontaktów działa inaczej

W Lithium nie można wpisać czyjegoś numeru telefonu ani adresu email i zacząć pisać. Serwer nie pośredniczy w nawiązywaniu kontaktów i nie ma do tego żadnego narzędzia.

Żeby dodać kontakt, obie strony muszą wymienić między sobą specjalne kody — przez dowolny kanał poza Lithium. Może to być email, SMS, telefon, kartka papieru. Po wymianie kodów aplikacja pokazuje ciąg sześciu emoji, które obie strony powinny potwierdzić głosowo lub osobiście. Te emoji to kryptograficzny odcisk wzajemnej tożsamości — jeśli się zgadzają, rozmówcy są pewni, że nikt nie wcisnął się pośrodku i nie udaje, że jest kimś innym.

Jest to bardziej skomplikowane niż "dodaj kontakt z książki telefonicznej". Jest też odporne na scenariusze, które w innych komunikatorach byłyby trudne do wykrycia.

---

## Szyfrowanie na każdym poziomie

Wiadomości w Lithium są szyfrowane kilkakrotnie, na różnych warstwach.

Po pierwsze — szyfrowanie między rozmówcami. Wiadomość jest zaszyfrowana kluczami specyficznymi dla danej pary osób. Nawet jeśli ktoś przechwyci ją na serwerze, nie może jej przeczytać.

Po drugie — szyfrowanie transportu. Połączenie między aplikacją a serwerem jest szyfrowane oddzielnie, przy użyciu kluczy sesji, które żyją tylko przez 60–120 sekund. Po tym czasie nie można odszyfrować wcześniejszego ruchu sieciowego nawet mając wszystkie klucze długoterminowe.

Po trzecie — szyfrowanie danych lokalnych. Wszystko, co jest zapisane na dysku urządzenia, jest zaszyfrowane kluczem wyprowadzanym z hasła użytkownika w połączeniu z komponentem pobranym z serwera. Kradzież dysku bez znajomości hasła nic nie daje.

Po czwarte — serwer dokłada własną warstwę izolacji nad zaszyfrowanymi już wiadomościami. Każda wiadomość oczekująca na odebranie jest dodatkowo owijana jednorazowym kluczem, który istnieje wyłącznie w pamięci serwera i nigdy nie trafia na dysk. Jeśli serwer zostanie zrestartowany, te klucze znikają i oczekujące paczki danych stają się trwale niedostarczalne — serwer traci zdolność ich przekazania odbiorcy. Treść wiadomości i tak była dla serwera nieczytelna od chwili wysłania; ta warstwa sprawia jedynie, że nawet sam relay nie jest w stanie "przekazać" czegoś ponownie.

---

## Czym Lithium nie jest

Lithium nie jest wygodny w codziennym użyciu. Nie ma grup, kanałów, statusów obecności, reakcji na wiadomości, wiadomości głosowych. Nie synchronizuje historii między urządzeniami. Nie działa bez połączenia z internetem. Nie wysyła powiadomień push.

Wszystkie te braki są świadome. Każda z tych funkcji wymagałaby albo zaangażowania serwera w operacje kryptograficzne, albo przechowywania dodatkowych danych, albo regularnego kontaktu z serwerem — i każda z nich w jakiś sposób zwiększałaby zaufanie, które Lithium stara się wyeliminować.

Lithium nie jest dla każdego. Jest dla sytuacji, w których stawka jest na tyle wysoka, że wygoda schodzi na drugi plan.

---

## Jedno zdanie podsumowania

Lithium jest komunikatorem zaprojektowanym tak, żeby nawet jego twórcy nie byli w stanie przeczytać twoich rozmów — i żeby to była właściwość matematyczna, a nie obietnica.