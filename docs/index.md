# Dokumentacja Lithium

## Dla audytorów i integratorów

- [security-model.md](security-model.md) — model zaufania, priorytety, założenia, świadome kompromisy, widoczność serwera per request, prymitywy, klasyfikacja ustaleń audytowych
- [threat-model.md](threat-model.md) — strukturalny model zagrożeń: klasy przeciwnika, ich zdolności, obrona i ryzyko rezydualne
- [data-lifecycle.md](data-lifecycle.md) — cykl życia danych i inwentarz prywatności: gdzie spoczywają, retencja, kto co widzi
- [key-hierarchy.md](key-hierarchy.md) — katalog i hierarchia wszystkich kluczy: derywacja, przechowywanie, czas życia, analiza wycieku
- [design-decisions.md](design-decisions.md) — rejestr decyzji projektowych („dlaczego"): uzasadnienia, odrzucone alternatywy, koszty
- [glossary.md](glossary.md) — słownik pojęć własnych Lithium
- [versioning.md](versioning.md) — wersjonowanie formatów i filozofia ewolucji protokołu
- [kyberbox.md](kyberbox.md) — analiza bezpieczeństwa schematu KyberBox: przepływ kluczy, właściwości, założenia, otwarte pytania
- [crypto-protocol.md](crypto-protocol.md) — specyfikacja protokołu kryptograficznego: transport (Shake/Session), E2E (WireV1), mailbox, cykl życia kluczy
- [ipc-reference.md](ipc-reference.md) — referencja protokołu IPC daemona: format, autoryzacja, pełna lista komend
- [deploy-instructions.md](deploy-instructions.md) — wdrożenie `lithiums`: zmienne środowiskowe, providery master key, Docker/Docker Compose, zmienne `lithiumd`
- [daemon-runtime.md](daemon-runtime.md) — runtime daemona `lithiumd`: model procesu, system tray, cykl życia, endpoint IPC, układ katalogu danych
- [development.md](development.md) — budowanie, zależności systemowe, feature flagi, testy, fuzzing

## Dokumentacja komponentów

- [`lithium_core.md`](lithium_core.md) — kryptografia, typy sekretne, zarządzanie kluczami, format plików kluczy
- [`lithiumd.md`](lithiumd.md) — daemon klienta: IPC, E2E, mailbox, SQLite, PasswordFileMkProvider
- [`lithiums.md`](lithiums.md) — serwer relay: REST API, middleware, transport, schemat PostgreSQL
- [`lithiumg.md`](lithiumg.md) — GUI: maszyna stanów, model wątków

## Przegląd projektu

- [`README.md`](../README.md) — opis projektu, architektura, właściwości bezpieczeństwa, wdrożenie