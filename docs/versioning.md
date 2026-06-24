# Wersjonowanie i ewolucja protokołu

Jak Lithium wersjonuje swoje formaty i jaka jest obecna filozofia ich zmiany. Konkretne formaty opisuje [crypto-protocol.md](crypto-protocol.md); listę etykiet — [key-hierarchy.md](key-hierarchy.md).

## Dwie warstwy wersjonowania

**1. Etykiety domeny `/vN`** — łańcuchy używane jako `info` w HKDF, AAD w AEAD oraz konteksty KyberBox. Ich rolą jest **separacja domen**: ten sam materiał klucza pod różną etykietą daje różne klucze, a szyfrogram z jedną etykietą nie odszyfruje się pod inną. Przykłady: `kek/v1`, `lithium/db-dek/v1`, `lithium/mbox/address/v1`, `lithiumd/e2e-msg/v1`, `lithiumd/pair-commit/v1`, `lithiumd/contact-verify-emoji/v1`, `user-opaque-record/v1`, `lithium/send-pow/v1`. Konteksty transportu są budowane per endpoint przez `ctx_req`/`ctx_resp` (np. `shake-req`, `msg_send-resp`).

**2. Bajty `VER` + magici** — w formatach binarnych. Ich rolą jest **identyfikacja i odrzucenie** nieznanego formatu (fail-closed). Aktualny stan:

| Format | Magic | Wersja |
|--------|-------|--------|
| Blob AEAD | — | 1 (pierwszy bajt) |
| KyberBox (`seed_enc`) | — | 1 (+ `kem_id=1`, `aead_id=1`) |
| Plik klucza `.keyf` | `KEYF` | 1 |
| Wiadomość E2E `WireV1` | `LM1` | 1 |
| Kod zaproszenia `lci1:` | `LCI1` | 1 |
| Plik MK | `LMK1` | 1 |
| `server.identity` | `LITHIUPK` | 1 |
| Owinięcie DEK (OPAQUE) | — | 1 (`DEK_WRAP_VER`) |
| `id_enc` / wiadomość serwera | — | 1 (`UIDENC_VER` / `MSG_VER`) |

## Postawa: „v1-only, fail-closed"

Wszystko jest dziś w wersji **1**. Dekodery **odrzucają** każdy inny bajt wersji zamiast próbować interpretacji — nie ma negocjacji wersji ani równoległej obsługi wielu wersji. Zła wersja, zły magic lub zła długość to twardy błąd (np. blob AEAD z wersją ≠ 1 nie deszyfruje się; `lci1:` z wersją ≠ 1 jest odrzucany). To celowy wybór: brak „miękkiej" tolerancji ogranicza powierzchnię ataku na parsery.

Jedyny wyjątek forward-compat: `server.identity` **ignoruje nieznane tagi TLV** przy deserializacji (pozwala dodać przyszłe klucze bez zrywania starych klientów), ale cztery znane tagi muszą wystąpić i mieć dokładną długość.

## Pinowanie wartości

Każda etykieta, magic i bajt wersji są przypięte testami `registry_values_are_pinned` (`lithium_core/src/labels.rs`, `lithiums/src/labels.rs`, `lithium_core/src/contract/protocol.rs` i odpowiedniki E2E). Test asercją sprawdza dokładny bajt-w-bajt. Konsekwencja: etykieta/wersja to **kontrakt**, nie przypadkowy string — przypadkowa zmiana (literówka, refaktor) wywala testy, zanim trafi na wire. Każda celowa zmiana wymaga równoległej aktualizacji pinu.

## Filozofia ewolucji

Lithium **nie jest jeszcze wdrożony** — nie ma zainstalowanej bazy klientów ani danych produkcyjnych, z którymi trzeba zachować kompatybilność wire. Wynika z tego zasada **correct-by-construction ponad kompatybilność wsteczną**: gdy format musi się zmienić, zmienia się go czysto, a nie obrasta shimami zgodności.

W praktyce, zmiana formatu = jeden spójny krok:
1. Zmień bajt `VER` lub etykietę (`/v1` → `/v2`).
2. Zaktualizuj **jednocześnie** enkoder i dekoder po obu stronach.
3. Zaktualizuj test pinujący.
4. **Nie** dodawaj ścieżki obsługi starej wersji ani feature-flag — `PROJECT_STYLE.md`/`CLAUDE.md` zakazują backwards-compat shimów i re-exportów dla usuniętego kodu.

Gdy projekt zostanie wdrożony, ta postawa będzie musiała się zmienić na właściwą migrację (równoległa obsługa `vN`/`vN+1`, okno przejściowe) — to świadomy, przyszły punkt zwrotny, nie obecny stan.

## Co jest sprzężone (nie wersjonować w izolacji)

Niektóre wartości są ze sobą związane i ich zmiana wymaga rekompensaty gdzie indziej:

- **Konteksty kierunkowe transportu** (`-req`/`-resp`) i etykiety AEAD muszą być identyczne po obu stronach wrapa — inaczej deszyfracja zawodzi.
- **Długość SAS i commit-reveal** są sprzężone (patrz [design-decisions.md](design-decisions.md) #5): skrócenie jednego bez drugiego ponownie otwiera offline-grind.
- **Etykiety derywacji** (`combined/v1`, `db-dek/v1`, …) definiują tożsamość wyprowadzonych kluczy — zmiana wersji etykiety unieważnia wszystkie dane zaszyfrowane starym kluczem.
