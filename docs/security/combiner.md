# Combiner story — hybrydowa kompozycja KyberBox

Ten dokument uzasadnia **kombinator hybrydowy** użyty w `lithium_core/src/crypto/kyberbox.rs`:
co dokładnie składa klasyczną gałąź (X25519) z postkwantową (ML-KEM-1024), czym różni się od
standaryzowanego X-Wing i jakie pytania zostają otwarte dla audytora. Jest pisany jako wprost
materiał do audytu — kombinator jest produktem, więc jego poprawność jest centralnym ustaleniem.

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

## 2. Dlaczego nie X-Wing

Pierwsze pytanie kryptografa kupującego brzmi: „czemu nie X-Wing i czy Twój kombinator jest
dowiedlnie poprawny?". X-Wing to standaryzowany hybrydowy KEM:

```
X-Wing: ML-KEM-768 + X25519, jeden kombinator:
  ss = SHA3-256( ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || XWingLabel )
```

Lithium różni się **trzema** rzeczami i z każdej wynika, że X-Wing nie wkleja się 1:1:

1. **Poziom bezpieczeństwa.** Lithium używa ML-KEM-**1024** (NIST kategoria 5), nie ML-KEM-768
   (kategoria 1) jak X-Wing. Cała reszta stosu (ML-DSA-87) jest dobrana do tej samej kategorii.
2. **KEM vs AEAD.** X-Wing zwraca wspólny sekret `ss` do dalszego użycia. KyberBox jest pełnym
   szyfrowaniem wiadomości — gałąź ML-KEM transportuje świeży `seed_plain` (KEM-DEM), a nie
   bezpośrednio dostarcza materiał klucza do konkatenacji.
3. **Struktura kombinatora.** X-Wing konkatenuje *oba* wspólne sekrety jako wejście jednego
   SHA3-256 (z transkryptem `ct_x25519 || pk_x25519`). Lithium używa HKDF z `ecdh_key` jako IKM
   i `seed_plain` jako **saltem** — asymetria salt-vs-IKM zamiast symetrycznej konkatenacji.

Wniosek dla audytu: potrzebna jest **odpowiedź** uzasadniająca własny kombinator, nie adopcja
X-Wing. Poniższe pytania są tą odpowiedzią postawioną wprost.

## 3. Argument bezpieczeństwa hybrydy

Twierdzenie konstrukcyjne: żeby policzyć `base_key`, atakujący musi znać **oba** wejścia HKDF —
`ecdh_key` (co wymaga złamania X25519, bo `ecdh_ss` jest sekretny) **oraz** `seed_plain` (co
wymaga złamania ML-KEM-1024, bo `seed_plain` jest odzyskiwany wyłącznie przez decapsulację). O ile
HKDF-SHA256 nie ma słabości pozwalającej policzyć wyjście bez znajomości jednego z (IKM, salt),
złamanie tylko jednej gałęzi nie wystarcza. Świeży `seed_plain` per wiadomość daje też unikalny
`base_key` per wiadomość (świeżość klucza nawet przy reużyciu kluczy publicznych odbiorcy).

To twierdzenie wynika z zamierzeń projektowych i analizy konstrukcji — **nie z formalnego
dowodu**. Formalizacja w standardowym modelu hybrid-KEM jest właśnie tym, czego oczekujemy od
audytu.

## 4. Otwarte pytania do audytora

- **Q1 — `SHA256(ct_kem)` jako salt HKDF.** W derywacji `aead_key_kem` salt jest hashem
  ciphertextu ML-KEM widocznego dla atakującego; ten sam hash służy jako sprawdzenie integralności
  blobu. Używanie hashu wartości wybieralnej/widocznej dla atakującego jako salta KDF jest
  niestandardowe. Argument: `ss_kem` jest właściwym materiałem klucza, a salt musi tylko być
  niesekretny i unikalny per ciphertext. Pytanie: czy atakujący wybierający `ct_kem` (przez
  złośliwą wiadomość) może wymusić salt osłabiający wynikowe `aead_key_kem` w dowodzie HKDF?

- **Q2 — salt-vs-IKM dla gałęzi PQ.** W `base_key` gałąź klasyczna jest IKM, a gałąź PQ
  (`seed_plain`) jest saltem — w przeciwieństwie do X-Wing, gdzie oba sekrety są symetrycznie
  konkatenowane jako wejście. Pytanie: czy ta asymetria zachowuje pełną hybrid-security, tj. czy
  przeciwnik łamiący jedną gałąź (klasyczną *albo* PQ) nadal nie zyskuje żadnej przewagi nad
  `base_key`?

- **Q3 — `ecdh_ss` jako IKM bez salta.** `ecdh_key` jest wyprowadzany HKDF z `salt=brak`. Wejście
  jest sekretne (wynik DH), więc standardowo brak salta jest dopuszczalny — do potwierdzenia w tym
  konkretnym złożeniu.

- **Q4 — filtr integralności przed decapsulacją.** `decrypt_kyber_seed` weryfikuje
  `SHA256(ct_kem)` względem zapisanego salta *przed* decapsulacją, co ma ograniczać użycie blobu
  jako wyroczni decapsulacji. Pytanie: czy ten deterministyczny filtr wystarcza wobec atakującego
  adaptacyjnego w modelu IND-CCA2 ML-KEM?

## 5. Co dostaje audytor

- Kod kombinatora: `lithium_core/src/crypto/kyberbox.rs` (oraz `crypto/kdf.rs`, `crypto/aead.rs`).
- Opis wire i przepływu kluczy: [`kyberbox.md`](kyberbox.md).
- Granice odpowiedzialności biblioteki: [`lithium_core-threat-model.md`](lithium_core-threat-model.md).
- Niniejsze pytania Q1–Q4 jako zakres pytań do rozstrzygnięcia.
