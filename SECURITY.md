# Polityka bezpieczeństwa

> **Status: przedaudytowy.** Implementacja nie przeszła niezależnego audytu kryptograficznego i nie ma wydań produkcyjnych. Używasz jej na własne ryzyko — nie do ochrony realnie wrażliwej komunikacji przed audytem.

## Zgłaszanie podatności

Zgłoszenia kieruj prywatnie na **oktawia.handerek@gmail.com**. Nie otwieraj publicznego issue dla podatności.

PGP do zaszyfrowanych zgłoszeń: _odcisk klucza do uzupełnienia_. Do czasu jego publikacji nie umieszczaj wrażliwego PoC w treści maila — poproś najpierw o klucz.

Prosimy o coordinated disclosure: daj czas na poprawkę, zanim ujawnisz szczegóły publicznie (domyślnie do 90 dni od potwierdzenia). Potwierdzenie zgłoszenia — najszybciej jak to możliwe; to mały projekt, nie ma całodobowego dyżuru.

## Zanim zgłosisz

Lithium ma świadome kompromisy projektowe i zachowania, które wyglądają jak luki, a są celowe (serwer z założenia jest hostile relay i widzi metadane opisane w modelu; część operacji jest celowo bolesna lub nieodwracalna). Zanim zgłosisz, sprawdź w `docs/security-model.md`:

- [Co powinno być audytowane jako realny problem](docs/security/security-model.md#co-powinno-być-audytowane-jako-realny-problem)
- [Czego nie należy raportować jako podatności bez kontekstu](docs/security/security-model.md#czego-nie-należy-raportować-jako-podatności-bez-kontekstu)
- [Klasyfikacja ustaleń audytowych](docs/security/security-model.md#klasyfikacja-ustaleń-audytowych)

Pełny model zaufania i granice odpowiedzialności: [`docs/security-model.md`](docs/security/security-model.md), [`docs/threat-model.md`](docs/security/threat-model.md), [`docs/kyberbox.md`](docs/security/kyberbox.md).

## Zakres

W zakresie: `lithium_core` (krypto, KDF, typy sekretne), `lithiumd` (IPC, E2E, mailbox), `lithiums` (transport, rate limiting). Poza zakresem: właściwości, które model zaufania świadomie akceptuje jako koszt — widoczność metadanych po stronie serwera, brak gwarancji dostarczenia, brak recovery dla utraconego materiału kluczy.

## Wspierane wersje

Projekt przedaudytowy, bez wydań produkcyjnych. Wspierany jest wyłącznie bieżący `main`.
