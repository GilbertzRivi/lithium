# Dokumentacja Lithium

## Dla audytorów i integratorów

- [security-model.md](security-model.md) — model zaufania, priorytety, założenia, świadome kompromisy, klasyfikacja ustaleń audytowych
- [kyberbox.md](kyberbox.md) — analiza bezpieczeństwa schematu KyberBox: przepływ kluczy, właściwości, założenia, otwarte pytania
- [crypto-protocol.md](crypto-protocol.md) — specyfikacja protokołu kryptograficznego: transport (Shake/Session), E2E (WireV1), mailbox, cykl życia kluczy
- [ipc-reference.md](ipc-reference.md) — referencja protokołu IPC daemona: format, autoryzacja, pełna lista komend

## Dokumentacja komponentów

- [`lithium_core/README.md`](../lithium_core/README.md) — kryptografia, typy sekretne, zarządzanie kluczami, format plików kluczy
- [`lithiumd/README.md`](../lithiumd/README.md) — daemon klienta: IPC, E2E, mailbox, SQLite, PasswordFileMkProvider
- [`lithiums/README.md`](../lithiums/README.md) — serwer relay: REST API, middleware, transport, schemat PostgreSQL
- [`lithiumg/README.md`](../lithiumg/README.md) — GUI: maszyna stanów, model wątków

## Przegląd projektu

- [`README.md`](../README.md) — opis projektu, architektura, właściwości bezpieczeństwa, wdrożenie