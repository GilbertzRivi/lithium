# Reproducible build

Architektura Lithium zamyka koercję po stronie **serwera** (operator nie ma plaintextu). Nie
zamyka jej sama z siebie po stronie **dystrybucji klienta**: zmuszony, podpisany, backdoorowany
build binarki klienta. Reprodukowalny build jest odpowiedzią — pozwala każdemu zweryfikować, że
opublikowana binarka `lithiumd` powstała z publicznego źródła. Zmuszony backdoor nie zreprodukuje
się bit w bit, więc staje się wykrywalny.

To jest prerekwizyt dalszego hardeningu dystrybucji (Faza 5: binary transparency log C2, progowy
podpis release C3).

## Co jest pinowane

- **Zależności** — `Cargo.lock` w repo; build używa `--locked`, więc dokładny zestaw crate'ów
  jest odtwarzalny.
- **Kompilator** — `rust-toolchain.toml` pinuje `1.96.0`; obraz bazowy kontenera
  (`rust:1.96.0-bookworm`) jest tej samej wersji.
- **Środowisko buildu** — kontener `build/Dockerfile` z pinowanymi bibliotekami systemowymi
  (GTK3 + Ayatana app indicator do linkowania `lithiumd`).
- **Niedeterminizm** — `RUSTFLAGS=--remap-path-prefix` usuwa absolutne ścieżki buildu z binarki
  (debug info, stringi panic); `SOURCE_DATE_EPOCH` ustala znaczniki czasu.

## Jak odtworzyć

Z katalogu głównego repo:

```bash
docker build -f build/Dockerfile -t lithium-repro .
docker run --rm lithium-repro            # wypisuje sha256 binarki
```

## Jak zweryfikować opublikowaną binarkę

1. Sklonuj repo na tagu wydania, którego dotyczy binarka.
2. Zbuduj jak wyżej i policz `sha256sum target/release/lithiumd` w kontenerze.
3. Porównaj z sumą opublikowaną przy wydaniu. Identyczna suma = binarka odpowiada źródłu.

CI (`.github/workflows/reproducible-build.yml`) robi to automatycznie: buduje `lithiumd`
**dwukrotnie** (drugi raz bez cache) i sprawdza, że obie binarki mają identyczne sha256.
Rozbieżność łamie build.

## Znane źródła niedeterminizmu i ich domknięcie

| Źródło | Domknięcie |
|---|---|
| Wersja kompilatora | `rust-toolchain.toml` + pin obrazu bazowego |
| Zestaw zależności | `Cargo.lock` + `--locked` |
| Absolutne ścieżki buildu | `--remap-path-prefix` |
| Znaczniki czasu | `SOURCE_DATE_EPOCH` |
| Biblioteki systemowe | pinowane w `build/Dockerfile` |

## Hardening na przyszłość

- **Pin obrazu bazowego po digest.** Zamienić tag `rust:1.96.0-bookworm` na
  `rust:1.96.0-bookworm@sha256:<digest>`, żeby ponownie wypchnięty tag nie mógł podmienić
  toolchaina.
- **Binary transparency log (C2)** — append-only publiczny log artefaktów (Sigstore / CT-style),
  żeby targetowany podstawiony build zostawiał publiczny ślad.
- **Progowy / wieloosobowy podpis release (C3)** — żeby nikt sam (łącznie z maintainerem) nie
  wypuścił update'u.
