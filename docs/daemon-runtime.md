# Runtime daemona lithiumd — model procesu, system tray, cykl życia

Dokument opisuje, jak proces `lithiumd` jest zbudowany i jak się uruchamia, restartuje oraz zamyka. Komendy IPC opisuje [ipc-reference.md](ipc-reference.md); ten plik dotyczy samego runtime'u procesu (`lithiumd/src/lib.rs`, `main.rs`, `tray.rs`, `util.rs`).

## Dlaczego `main()` nie jest `#[tokio::main]`

System tray musi być właścicielem głównego wątku procesu, dlatego start jest rozdzielony na dwa wątki (`lithiumd/src/lib.rs`):

- **Wątek główny** uruchamia `tray::run` — pętlę menu zasobnika.
- **Osobny `std::thread`** tworzy runtime Tokio i wykonuje cały asynchroniczny daemon (`daemon_async`).

`main()` (`lithiumd/src/main.rs`) tylko woła `lithiumd::run()` i mapuje błąd na `eprintln!("fatal: {e}")` + `exit(1)`. Na Windows `#![cfg_attr(windows, windows_subsystem = "windows")]` tłumi okno konsoli.

## Prymitywy łączące oba wątki

| Prymityw | Kierunek | Rola |
|----------|----------|------|
| `watch::channel<bool>` (`stop_tx`/`stop_rx`) | tray → daemon | tray sygnalizuje daemonowi zatrzymanie |
| `Arc<AtomicBool>` (`daemon_done`) | daemon → tray | daemon informuje tray, że zakończył pracę |
| `oneshot::channel<()>` (`shutdown_tx`/`shutdown_rx`) | IPC → daemon | komenda IPC `shutdown` przerywa pętlę daemona |

## Pętla daemona (`daemon_async`)

Daemon czeka w jednym `tokio::select!` na cztery zdarzenia (`lithiumd/src/lib.rs`):

```
tokio::select! {
    _ = ipc_task        => {}   // zadanie nasłuchu IPC zakończyło się
    _ = shutdown_rx     => {}   // komenda IPC `shutdown`
    _ = stop_rx.changed() => {} // sygnał z tray (Close/Restart)
    _ = signal          => {}   // SIGTERM lub Ctrl+C (na Unix), Ctrl+C (Windows)
}
```

Każda z tych ścieżek rozwija ten sam `select!` i kończy daemona. Po jego zakończeniu wątek daemona ustawia `daemon_done = true`.

## System tray (`tray.rs`)

Menu zasobnika ma pozycje: nieaktywny nagłówek `Lithium`, separator, **Restart**, **Close**. Ikona to generowany programowo niebieski okrąg 32×32. Pętla tray:

1. Na Linuxie najpierw `gtk::init()`; pętla woła `gtk::main_iteration_do(false)` i co 16 ms sprawdza zdarzenia menu.
2. Kliknięcie **Restart** lub **Close** wysyła `stop.send(true)` (zatrzymuje daemona) i zwraca odpowiednią `Action`.
3. Jeśli `daemon_done` zrobi się `true` niezależnie (np. `shutdown` przez IPC), tray kończy z `Action::Close`.

**Degradacja headless:** jeśli `gtk::init()` zawiedzie albo `TrayIconBuilder::build()` się nie powiedzie (brak środowiska graficznego), tray degraduje się do `wait_daemon_done` — blokuje bez ikony, dopóki daemon nie zakończy pracy. Daemon działa wtedy normalnie, tylko bez ikony w zasobniku.

## Zamknięcie i restart

- **Close**, **SIGTERM**/Ctrl+C oraz IPC `shutdown` prowadzą do tego samego rozwinięcia `select!` i zakończenia daemona.
- Po zakończeniu pętli `tray::run` wątek daemona jest dołączany (`daemon_thread.join()`).
- **Restart** dodatkowo: po dołączeniu wątku daemona `run()` re-spawnuje bieżący plik wykonywalny (`std::env::current_exe()`), po czym kończy stary proces.
- `WipeLocal` (komenda IPC) najpierw bezpiecznie czyści `{data_dir}` (nadpisanie losowymi danymi, `fsync`, usunięcie — `util::wipe_dir_all`), a następnie zamyka daemona.

## Endpoint IPC i jego cykl życia

Endpoint jest wybierany przy starcie (`util::default_ipc_endpoint`):

- **Unix**: `LITHIUMD_SOCKET_PATH`, w przeciwnym razie `{XDG_RUNTIME_DIR}/lithiumd.sock`. Bez `XDG_RUNTIME_DIR` i bez override'u start kończy się błędem (brak bezpiecznej lokalizacji). Socket nasłuchuje z uprawnieniami właściciela; przy starcie `prepare_socket` usuwa nieaktualny socket z poprzedniego uruchomienia.
- **Windows**: named pipe `LITHIUMD_PIPE_NAME` (domyślnie `\\.\pipe\lithiumd`), `reject_remote_clients(true)`.

Polityka połączeń IPC (`util::load_ipc_policy`):

| Parametr | Zmienna | Domyślnie | Uwagi |
|----------|---------|-----------|-------|
| Maks. równoległych połączeń | `LITHIUMD_IPC_MAX_CONNECTIONS` | `1` | min 1 |
| Idle timeout | `LITHIUMD_IPC_IDLE_TIMEOUT_SECS` | `300` | min 5 |
| Dozwolony UID (Linux) | `LITHIUMD_IPC_ALLOWED_UID` | brak | niezgodny UID zrywa połączenie bez odpowiedzi JSON |

## Start procesu, krok po kroku

`run()` (`lithiumd/src/lib.rs`) wykonuje kolejno:

1. `util::default_data_dir()` — rozwiązanie katalogu danych (patrz niżej).
2. `prepare_private_dir` — tworzy katalog danych z uprawnieniami `0o700` (Unix).
3. `prepare_ipc_endpoint` — usuwa nieaktualny socket.
4. Wczytuje `server_url` (plik), ścieżkę `server.identity` (`LITHIUMD_SERVER_IDENTITY` lub `{data_dir}/server.identity`) oraz flagę `needs_register` (istnienie `registered.flag`).
5. Buduje `DaemonState`, startuje wątek daemona i `tray::run` na wątku głównym.

Keystore, `MkRotator`, lokalna baza i `ProtocolManager` nie są tworzone przy starcie — powstają dopiero po `unlock_keystore` / `unlock_storage` (patrz [ipc-reference.md](ipc-reference.md)).

## Układ katalogu danych

`default_data_dir()` zwraca `LITHIUMD_DATA_DIR`, a w razie braku platformowy katalog (Linux: `{XDG_DATA_HOME}/lithiumd` lub `~/.local/share/lithiumd`; Windows: `%LOCALAPPDATA%\Lithiumd`). Zawartość:

```
{data_dir}/                       (0o700)
├── keystore/
│   ├── user/
│   │   ├── mk.enc                Master Key opakowany hasłem danych (Argon2id + AES-256-GCM-SIV)
│   │   └── root.salt             losowa per-instalacja sól Argon2 do derywacji DEK
│   ├── pub/                      publiczne klucze (cache: ed25519.pub, x25519.pub, ...)
│   ├── priv/                     prywatne klucze (*.keyf, opakowane pod MK)
│   ├── secrets/                  sekrety pochodne (*.keyf, opakowane pod MK)
│   └── .rotate/                  tymczasowy katalog rotacji MK
├── storage/
│   └── lithiumd.sqlite           lokalna baza (kontakty, wiadomości, prekeys)
├── server.identity              klucze publiczne serwera (lub LITHIUMD_SERVER_IDENTITY)
├── server_url                   adres relay'a (tekst)
└── registered.flag              marker rejestracji (0o600)
```

Socket IPC **nie** leży w katalogu danych — domyślnie jest w `{XDG_RUNTIME_DIR}`. Formaty `mk.enc`, `*.keyf` i `server.identity` opisuje [crypto-protocol.md](crypto-protocol.md); schemat tabel `storage/lithiumd.sqlite` — [lithiumd.md](lithiumd.md). Szyfrowanie danych w spoczynku i model „dwóch czynników" (hasło + `server_dek`) opisuje [security-model.md](security-model.md).
