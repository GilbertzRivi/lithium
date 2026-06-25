# Model zagrożeń — biblioteka `lithium_core`

Ten dokument jest **węższy** niż [`threat-model.md`](threat-model.md), który opisuje cały
komunikator (relay, transport, IPC, kradzież urządzenia, złośliwy peer). Tutaj zakresem jest sam
crate `lithium_core` jako biblioteka kryptograficzna i zarządzanie kluczami at-rest. Granica jest
istotna dla audytu: audytujemy ciasną powierzchnię biblioteki, nie aplikację.

## Zakres

W zakresie: dwa filary (`keys`/`secrets`, `crypto`) i helpery (`opaque`, `pow`, `passwords`,
`utils::store`). Poza zakresem (warstwy aplikacji w `lithiumd`/`lithiums`/`lithiumg`): sieć,
serwer relay, transport REST, handshake/invite, IPC, polityka cover-traffic, UX odblokowania.

## Co biblioteka gwarantuje (przy spełnionych założeniach z sekcji niżej)

- **Poufność wiadomości** — `crypto::kyberbox` (X25519 + ML-KEM-1024, AES-256-GCM-SIV).
  Hybrydowo: odzyskanie klucza wiadomości wymaga złamania **obu** gałęzi
  (patrz [`combiner.md`](combiner.md)).
- **Autentyczność/integralność** — `crypto::sign` (Ed25519 + ML-DSA-87, podwójny podpis), gdy
  wywołujący podpisuje i weryfikuje.
- **Ochrona kluczy at-rest** — klucze prywatne zapieczętowane pod master key dostarczanym przez
  `MkProvider` (plik lub TPM); typy sekretne zerują się przy drop; rotacja crash-safe z rewrap.
- **Odporność postkwantowa (harvest-now-decrypt-later)** — gałąź ML-KEM-1024 chroni nagrany dziś
  ruch przed przyszłym przeciwnikiem kwantowym.

## Założenia (odpowiedzialność wywołującego — granica biblioteki)

KyberBox i podpisy są prymitywami; bezpieczeństwo zależy od tego, że wywołujący dotrzyma:

- **Autentyczność kluczy publicznych odbiorcy.** KyberBox nie weryfikuje, że `peer_pub_x` ani
  `peer_k_pub` należą do zamierzonego odbiorcy. Podstawienie kluczy szyfruje dla złej strony.
  Wiązanie tożsamości to warstwa invite/handshake komunikatora, nie biblioteka.
- **Labely separacji domenowej.** Wszystkie konteksty (`ctx`, etykiety OPAQUE/POW/DEK) dostarcza
  wywołujący; muszą być unikalne per zastosowanie i spójne między stronami. Biblioteka jest
  celowo label-agnostyczna.
- **Brak ochrony przed replay na poziomie krypto.** KyberBox nie wiąże szyfrogramu z licznikiem
  ani stanem; detekcja replay jest w warstwie sesji/przechowywania komunikatora (okno na `step` +
  dedup `msg_id`) — patrz [`kyberbox.md`](kyberbox.md).
- **Brak bezpieczeństwa transportu.** TLS/anty-MITM na poziomie sieci to warstwa serwera/proxy.
- **Jakość losowości.** Konstrukcje polegają na systemowym CSRNG (świeże nonce i `seed_plain`).

## Widok przeciwnika (na poziomie biblioteki)

- **Tylko szyfrogram (`WirePayload`).** Musi złamać X25519 *i* ML-KEM-1024 (hybryda). Nonce
  reuse jest tolerowany przez AES-256-GCM-SIV jako defense-in-depth.
- **Pliki at-rest bez master key.** Klucze prywatne są zapieczętowane; bez MK (plik/TPM) są
  nieczytelne. Bezpieczeństwo redukuje się do ochrony MK przez `MkProvider`.
- **Przeciwnik adaptacyjny na decapsulacji.** Filtr `SHA256(ct_kem)` przed decapsulacją ma
  ograniczać użycie blobu jako wyroczni — wystarczalność wobec adaptacyjnego CCA to otwarte
  pytanie Q4 w [`combiner.md`](combiner.md).

## Forward secrecy / post-compromise

Biblioteka dostarcza prymitywy (świeży `seed_plain` per wiadomość, rotujące klucze RX). Same
gwarancje FS/PCS warstwy E2E (granica epok, pasywny vs aktywny przeciwnik, klucze tożsamości nie
rotują) są właściwością tego, jak `session.rs` używa KyberBox — opisane w
[`threat-model.md`](threat-model.md) (sekcja „Gwarancje forward secrecy i post-compromise
security").

## Poza zakresem (non-goals biblioteki)

- Dystrybucja kluczy / PKI / weryfikacja tożsamości.
- Odporność na kanały boczne ponad to, co dają użyte prymitywy. Uwaga: ML-KEM/ML-DSA pochodzą z
  `pqcrypto` (kod C) — założenia constant-time są dziedziczone z tych implementacji.
- Bezpieczeństwo pamięci procesu wobec lokalnego przeciwnika z tym samym UID (warstwa
  komunikatora: klasa 7 w [`threat-model.md`](threat-model.md)).
