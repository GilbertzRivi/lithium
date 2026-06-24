A. Katalog / hierarchia kluczy — najmocniejszy brak

Nie istnieje żaden dokument, który mapuje wszystkie klucze systemu naraz. Wiedza jest rozsmarowana po 4+ plikach.
Brakuje jednej tabeli/diagramu: nazwa → typ → z czego derywowany → gdzie przechowywany → czas życia/rotacja → kto
trzyma → co chroni, plus drzewo zależności:
MK → KEK → DEK(per-plik .keyf)
(password_root = Argon2(hasło, root.salt)) + server_dek → combined_root → db_dek
per-kontakt: X25519 + ML-KEM + Ed25519 + ML-DSA + 3× mailbox
RX keyring / bootstrap / prekeys / sesja transportowa / msg_key(serwer) / JWT secret / export_key(OPAQUE) / TPM
parent
To najcenniejszy artefakt audytowy — pozwala odpowiedzieć „jeśli wycieknie klucz X, co jest odsłonięte" i „co musi
być obecne, by odszyfrować Y". Dziś trzeba to składać z głowy.

B. Strukturalny model zagrożeń (zorientowany na przeciwnika)

security-model.md opisuje zaufanie i kompromisy, ale nie ma systematycznej macierzy klasa przeciwnika → zdolności →
obrona → ryzyko rezydualne. Klasy do wyliczenia: pasywny sieciowy, aktywny MITM, złośliwy/przejęty serwer,
złodziej urządzenia (bez hasła / z hasłem), złośliwy kontakt-peer, złośliwy lokalny proces tego samego UID, łańcuch
dostaw/zależności, „harvest-now-decrypt-later". To najwyższe piętro framingu bezpieczeństwa, na które cały projekt
odpowiada — dziś jest implicytne.

złodziej urządzenia (bez hasła / z hasłem), złośliwy kontakt-peer, złośliwy lokalny proces tego samego UID, łańcuch
dostaw/zależności, „harvest-now-decrypt-later". To najwyższe piętro framingu bezpieczeństwa, na które cały projekt
odpowiada — dziś jest implicytne.

C. Uzasadnienia decyzji projektowych (ADR / „dlaczego")

Warstwa ponad „co/jak": dlaczego hybryda PQ, dlaczego OPAQUE zamiast hasha/SRP, dlaczego GCM-SIV (odporność na
nonce-reuse), dlaczego adresowanie mailbox per-kontakt, dlaczego commit-reveal sprzężony z krótkim SAS, dlaczego
constant-rate cover traffic, dlaczego dwuczynnikowy DEK, dlaczego sealing TPM, dlaczego „utrata zamiast recovery".
Rationale tkwi w komentarzach kodu i kilku notkach — brak jednego rejestru decyzji. Audytor i nowy kontrybutor
wciąż pytają „czemu tak".

D. Słownik pojęć (glossary) — tani, wysokodźwigniowy

Dużo własnej terminologii: Kyberbox, WireV1, lci1, Shake/Session, commitment/bootstrap/ratchet/prekey, generacje
mailbox, cover traffic, party transcript, SAS, DEK/MK/server_dek, handler, one-time fetch, MkProvider. Brak
słownika — czytelnik rekonstruuje znaczenia z kontekstu.

E. Cykl życia danych / inwentarz prywatności (średni, częściowo pokryty)

Holistyczne „jakie dane istnieją, gdzie spoczywają (dysk klienta / serwer / RAM / sieć), retencja, kto widzi" —
częściowo w „co serwer widzi" + sekcjach storage, ale nie jako jeden widok data-flow.

F. Wersjonowanie i ewolucja protokołu (niższy priorytet)

Etykiety /v1 i bajty VER są pinowane testami, ale nie ma dokumentu o filozofii wersjonowania i obecnej postawie
„niewdrożone → brak kompatybilności wire".