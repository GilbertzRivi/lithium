# Combiner story — hybrydowa kompozycja KyberBox

Ten dokument uzasadnia **kombinator hybrydowy** użyty w `lithium_core/src/crypto/kyberbox.rs`:
co dokładnie składa klasyczną gałąź (X25519) z postkwantową (ML-KEM-1024), na jakim opublikowanym
wyniku stoi i jakie odchylenia od kanonu zostają do potwierdzenia przez audytora.

Punkt wyjścia: **kombinator nie jest nowy ani autorski.** Rdzeń (łączenie dwóch sekretów przez
HKDF, gdzie jeden jest IKM a drugi saltem) to **dualPRF / split-key-PRF combiner** — konstrukcja
opisana i udowodniona w literaturze. KyberBox jest jej instancją z kilkoma odchyleniami; to one,
nie sam pomysł, są przedmiotem walidacji.

Opis konstrukcji na poziomie wire i przepływu kluczy: [`kyberbox.md`](kyberbox.md). Tutaj skupiamy
się na *samym kombinatorze* i jego uzasadnieniu.

## 1. Konstrukcja (skrót)

KyberBox nie jest „KEM zwracającym wspólny sekret" — jest pełnym AEAD, który szyfruje `body` i
`headers`. Klucze pochodzą z dwóch niezależnych gałęzi złożonych przez HKDF-SHA256:

```
Gałąź klasyczna (X25519):
  ecdh_ss  = X25519(priv_x, peer_pub_x)
  ecdh_key = HKDF-SHA256(IKM=ecdh_ss, salt=brak, info="{ctx}/ecdh-key/v1")

Gałąź postkwantowa (ML-KEM-1024, KEM-DEM na losowym seedzie):
  seed_plain        <-- CSRNG (32B, świeży per wiadomość)
  (ss_kem, ct_kem)  = ML-KEM-1024.Encapsulate(peer_k_pub)
  aead_key_kem      = HKDF-SHA256(IKM=ss_kem, salt=SHA256(ct_kem), info="kemdem/...")
  seed_enc          = AES-256-GCM-SIV(seed_plain, aead_key_kem, ...)   # transport seeda

Kombinator:
  base_key   = HKDF-SHA256(IKM=ecdh_key, salt=seed_plain, info="{ctx}/base-key/v1")
  body_key   = HKDF-SHA256(IKM=base_key, salt=brak, info="{ctx}/body-key/v1")
  headers_key= HKDF-SHA256(IKM=base_key, salt=brak, info="{ctx}/headers-key/v1")
```

Kluczowy moment kombinacji: **`ecdh_key` jest IKM, a `seed_plain` (odzyskany przez ML-KEM) jest
saltem** w derywacji `base_key`. Obie gałęzie wchodzą do jednego HKDF; bez obu nie da się
policzyć `base_key`.

## 2. Na czym to stoi (literatura)

`base_key` to instancja kanonicznego kombinatora hybrydowego. Mapowanie:

```
Kanon (dualPRF combiner):   k        = HKDF-Expand( HKDF-Extract(salt=k1, IKM=k2), info=c1||c2 )
KyberBox:                   base_key = HKDF-Expand( HKDF-Extract(salt=seed_plain, IKM=ecdh_key), info="base-key/v1" )
```

Część `HKDF-Extract(salt, IKM)` jest dokładnie funkcją dual-PRF: pseudolosową, gdy *którykolwiek*
z dwóch argumentów jest losowy. To daje bezpieczeństwo hybrydowe (złamanie jednej gałęzi nie daje
przewagi). Źródła:

- **Bindel, Brendel, Fischlin, Gonçalves, Stebila**, *Hybrid Key Encapsulation Mechanisms and
  Authenticated Key Exchange*, PQCrypto 2019 (eprint 2018/903), sek. 3.2 — definiuje **dualPRF
  combiner** `PRF(dPRF(k1,k2), c1||c2)` z `dPRF=HKDF-Extract`, `PRF=HKDF-Expand`, modelowany na
  TLS 1.3; robustność pod założeniem HMAC=dual-PRF.
- **Bellare, Lysyanskaya**, generic validation of the dual-PRF assumption for HMAC.
- **Giacon, Heuer, Poettering**, *KEM Combiners* (PKC 2018) — **split-key PRF**: jeśli kombinator
  jest split-key-PRF i choć jeden składowy KEM jest IND-CCA, to złożony KEM jest IND-CCA.
- **draft-irtf-cfrg-hybrid-kems** (CFRG, w toku) — rekomendowane konstrukcje **UniversalCombiner**
  i **C2PRICombiner** (patrz sek. 3).
- **Barbosa et al.**, *X-Wing: The Hybrid KEM You've Been Looking For* (eprint 2024/039) — dowód,
  że szyfrogram ML-KEM można pominąć pod założeniem C2PRI.

Wniosek: nie potrzeba dowodu od zera. Potrzeba pokazać, że KyberBox mapuje się na te konstrukcje,
i ocenić odchylenia z sek. 4.

## 3. Czym różni się od X-Wing i kanonu

X-Wing to standaryzowany hybrydowy KEM:

```
X-Wing: ML-KEM-768 + X25519:
  ss = SHA3-256( ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || XWingLabel )
```

KyberBox różni się trzema rzeczami, ale tylko jedna jest realnym pytaniem:

1. **Poziom bezpieczeństwa (niegroźne).** ML-KEM-**1024** (kat. 5) zamiast 768 (kat. 1). Cały stos
   (ML-DSA-87) dobrany do kat. 5. Zmiana parametru, nie konstrukcji.
2. **KEM vs AEAD + KEM-DEM (do potwierdzenia).** X-Wing zwraca wspólny sekret; KyberBox to pełny
   AEAD, a gałąź ML-KEM transportuje świeży `seed_plain` (KEM-DEM). Skutek: założenie C2PRI dotyczy
   konstrukcji KEM-DEM, nie gołego ML-KEM — do potwierdzenia.
3. **Wiązanie szyfrogramów (realne pytanie).** Oba kombinatory IETF wiążą szyfrogram klasyczny
   `ct_T`:
   - **UniversalCombiner**: `KDF(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)` — wiąże oba.
   - **C2PRICombiner**: `KDF(ss_PQ, ss_T, ct_T, ek_T, label)` — wolno pominąć `ct_PQ` (= `ct_kem`)
     pod C2PRI, ale `ct_T` (= efemeryczny klucz X25519 `msg_x_pub`) zostaje.

   KyberBox **nie wiąże** w `info` ani `ct_kem`, ani `msg_x_pub` — `msg_x_pub` jest związany tylko
   implicite przez `ecdh_ss`. Pominięcie `ct_kem` jest zgodne z C2PRICombiner/X-Wing. Pominięcie
   jawnego `msg_x_pub` jest **odchyleniem od obu kombinatorów IETF** (patrz Q-D1 niżej).

## 4. Odchylenia do rozstrzygnięcia przez audytora

Numeracja D1–D4 spójna z `notes/brief.md`. Werdykt wstępny = co już mówi literatura; wymaga
potwierdzenia.

- **D1 — wiązanie szyfrogramów w `base_key` (najważniejsze).** Brak `ct_T` (`msg_x_pub`) w `info`,
  podczas gdy oba kombinatory IETF go wiążą (X25519 nie ma C2PRI). **Werdykt wstępny:** odchylenie
  realne; tania naprawa — związać `msg_x_pub` (i dla bezpieczeństwa `ct_kem`) w `info`, co czyni
  z KyberBoxa instancję UniversalCombinera. **Pytanie do audytora:** czy implicite wiązanie przez
  `ecdh_ss` wystarcza dla wymaganych własności binding (MAL-BIND-K-CT/PK), czy konieczne jest
  jawne związanie.
- **D2 — KEM-DEM na gałęzi PQ.** `seed_plain` (transportowany) zamiast gołego `ss_kem` jako wejście
  kombinatora. **Werdykt wstępny:** prawdopodobnie OK, ale C2PRI dotyczy wtedy konstrukcji KEM-DEM.
  **Pytanie:** czy KEM-DEM zachowuje C2PRI potrzebne do pominięcia `ct_kem`.
- **D3 — `ecdh_ss`/`ecdh_key` jako niejednostajny IKM bez salta.** Wynik X25519 nie jest jednostajny
  (clamping, zerowy najwyższy bit). **Werdykt wstępny:** pokryte — HKDF-Extract jest zaprojektowany
  pod niejednostajne IKM (Krawczyk 2010, RFC 5869), a w `base_key` losowy `seed_plain` jako salt
  dodatkowo pomaga. Najmniejsze ryzyko.
- **D4 — `SHA256(ct_kem)` jako salt HKDF w transporcie seeda.** Salt jest hashem widocznego
  ciphertextu. **Werdykt wstępny:** standardowo dopuszczalne (salt HKDF musi być tylko niesekretny
  i unikalny per ciphertext; właściwym materiałem klucza jest `ss_kem`). **Pytanie do audytora:**
  czy atakujący wybierający `ct_kem` może adaptacyjnie wymusić salt osłabiający `aead_key_kem`
  w modelu IND-CCA2 ML-KEM. Najbardziej wskazane do oka eksperta.

## 5. Co dostaje audytor

- Kod kombinatora: `lithium_core/src/crypto/kyberbox.rs` (oraz `crypto/kdf.rs`, `crypto/aead.rs`).
- Opis wire i przepływu kluczy: [`kyberbox.md`](kyberbox.md).
- Granice odpowiedzialności biblioteki: [`lithium_core-threat-model.md`](lithium_core-threat-model.md).
- Mapowanie na literaturę (sek. 2) i odchylenia D1–D4 (sek. 4) jako zakres do rozstrzygnięcia.
