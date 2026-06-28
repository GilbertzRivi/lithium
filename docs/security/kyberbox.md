# KyberBox — analiza bezpieczeństwa

Niniejszy dokument opisuje konstrukcję KyberBox z pliku `lithium_core/src/crypto/kyberbox.rs` oraz jej użycie w `lithiumd/src/e2e/session.rs`. Wyjaśnia cel kompozycji, dokładny przepływ kluczy, właściwości wynikające z konstrukcji, granice odpowiedzialności oraz otwarte pytania istotne z perspektywy audytu.

## Cel

KyberBox to hybrydowy schemat szyfrowania, który szyfruje dwa niezależne plaintexty (`body` i `headers`) w jednej operacji kryptograficznej, produkując trzy nieprzezroczyste blobs: `enc_body`, `enc_headers`, `seed_enc`. Konstrukcja jest zaprojektowana tak, żeby skompromitowanie samego komponentu klasycznego (X25519) nie wystarczyło do odszyfrowania wiadomości — atakujący musi przełamać również komponent post-kwantowy (ML-KEM-1024). Symetrycznie: skompromitowanie samego komponentu post-kwantowego też nie wystarczy.

KyberBox ma na celu zapewnienie wyłącznie **poufności**. Nie uwierzytelnia nadawcy, nie wiąże szyfrogramu z tożsamością nadawcy i nie chroni przed replay. Te odpowiedzialności leżą po stronie warstw wyżej.

## Prymitywy

Wszystkie wersje są przypięte w `Cargo.lock`.

| Prymityw | Implementacja | Wersja |
|---|---|---|
| X25519 ECDH | `x25519-dalek` / `curve25519-dalek` | 2.0.1 / 4.1.3 |
| ML-KEM-1024 | `pqcrypto-mlkem` (PQClean `ml-kem-1024`) | 0.1.1 |
| AES-256-GCM-SIV | `aes-gcm-siv` | 0.11.1 |
| HKDF-SHA256 | `hkdf` + `sha2` | 0.12.4 / 0.10.9 |
| CSRNG | `rand::rngs::SysRng` | — |

Implementacja ML-KEM-1024 pochodzi z PQClean (`ml-kem-1024`, czysta implementacja referencyjna w C) — nie z katalogu `kyber1024`, który odpowiada przedstandardowemu draftowi CRYSTALS-Kyber (oba katalogi istnieją w bundlowanym drzewie PQClean, ale są niespójne na poziomie formatu i nie są wzajemnie kompatybilne). Potwierdza to prefiks FFI `PQCLEAN_MLKEM1024_CLEAN_` oraz stała `PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES = 32`, zgodna z FIPS 203. Ścieżki AVX2 i NEON są domyślnie włączone.

## Przepływ kluczy

Po stronie szyfrowania wywołujący dostarcza:
- `priv_x`: efemeryczny klucz prywatny X25519 nadawcy (generowany świeżo per wiadomość w `session.rs`)
- `peer_pub_x`: klucz publiczny X25519 odbiorcy (jego zareklamowany klucz reply/ratchet)
- `peer_k_pub`: klucz publiczny ML-KEM-1024 odbiorcy
- `body`, `headers`: plaintexty
- `ctx`: string kontekstu do separacji domenowej (`"lithiumd/e2e-msg/v1"` w praktyce)

```
seed_plain (32B) <-- CSRNG
msg_x_priv (32B) <-- CSRNG  -->  msg_x_pub (wysyłany jako from_x_pub w WireV1)

Krok 1: ECDH
  ecdh_ss  = X25519(msg_x_priv, peer_pub_x)
  ecdh_key = HKDF-SHA256(IKM=ecdh_ss, salt=brak, info="{ctx}/ecdh-key/v1")

Krok 2: Szyfrowanie seed (ścieżka ML-KEM)
  (ss_kem, ct_kem) = ML-KEM-1024.Encapsulate(peer_k_pub)
  aead_key_kem     = HKDF-SHA256(IKM=ss_kem, salt=SHA256(ct_kem),
                                 info="kemdem/kyber-mlkem1024/v1")
  aad_seed         = [0x01] || "kyberbox/v1|kem=mlkem1024|aead=aes256-gcm-siv|"
                   || [0x01, 0x01, 0x01, 0x20] || SHA256(ct_kem)
                   || "{ctx}/seed/v1"
  seed_enc         = [naglowek 36B] || [u16be len(ct_kem)] || ct_kem
                   || AES-256-GCM-SIV(seed_plain, aead_key_kem, nonce_s, aad_seed)

Krok 3: Klucz bazowy (kombinacja obu sciezek)
  base_key = HKDF-SHA256(IKM=ecdh_key, salt=seed_plain, info="{ctx}/base-key/v1")

Krok 4: Szyfrowanie payloadow
  body_key    = HKDF-SHA256(IKM=base_key, salt=brak, info="{ctx}/body-key/v1")
  headers_key = HKDF-SHA256(IKM=base_key, salt=brak, info="{ctx}/headers-key/v1")
  enc_body    = [0x01] || nonce_b || AES-256-GCM-SIV(body, body_key, nonce_b,
                                                       "{ctx}/body/v1")
  enc_headers = [0x01] || nonce_h || AES-256-GCM-SIV(headers, headers_key, nonce_h,
                                                       "{ctx}/headers/v1")

Wynik: WirePayload { enc_body, enc_headers, seed_enc }
```

Wszystkie nonce (`nonce_s`, `nonce_b`, `nonce_h`) to 12 losowych bajtów z CSRNG, generowanych niezależnie przy każdym wywołaniu szyfrowania.

Deszyfrowanie odwraca kolejność: parsuje `seed_enc`, weryfikuje `SHA256(ct_kem)` względem zapisanego salta *przed* decapsulacją, decapsuluje `ss_kem`, wyprowadza `aead_key_kem`, odszyfrowuje `seed_plain`, następnie odtwarza łańcuch kluczy z `ecdh_key` i `seed_plain` i odszyfrowuje body oraz headers.

## Właściwości wynikające z konstrukcji

Poniższe właściwości wynikają z zamierzeń projektowych i analizy konstrukcji. KyberBox nie był poddany formalnej analizie ani zewnętrznemu audytowi — podane własności są tym, co konstrukcja *powinna* zapewniać, o ile użyte prymitywy spełniają swoje standardowe założenia bezpieczeństwa.

**Bezpieczeństwo hybrydowe.** `base_key` jest wyprowadzony z obu gałęzi: `ecdh_key` (ścieżka X25519) oraz `seed_plain` (odzyskany przez ML-KEM). Konkretnie: `seed_plain` jest saltem HKDF w derywacji `base_key`, a `ecdh_key` jest IKM. Żeby obliczyć `base_key` bez obu wejść, atakujący musiałby złamać X25519 (żeby obliczyć `ecdh_key` bez klucza prywatnego) lub ML-KEM-1024 (żeby odzyskać `seed_plain` bez klucza prywatnego) — o ile HKDF-SHA256 nie ma słabości pozwalającej pominąć jedno z wejść. Obie gałęzie są niezależne i według założeń konstrukcji obie są konieczne. Ta konstrukcja nie jest autorska: `HKDF-Extract(salt, IKM)` z jednym sekretem na każdej pozycji to znany **dualPRF / split-key-PRF combiner** (Bindel et al., PQCrypto 2019; Giacon et al., PKC 2018), którego robustność (złamanie jednej gałęzi nie daje przewagi) jest udowodniona pod założeniem, że HMAC jest dual-PRF (Bellare-Lysyanskaya). Mapowanie KyberBoxa na ten kombinator i odchylenia od niego: [`combiner.md`](combiner.md).

**Świeżość klucza per wiadomość.** Nawet jeśli klucze publiczne X25519 i ML-KEM-1024 odbiorcy są wielokrotnie używane dla kolejnych odebranych wiadomości (co ma miejsce do momentu, aż odbiorca wyśle odpowiedź), każda wiadomość generuje świeże `seed_plain` przez encapsulację ML-KEM. Ponieważ `seed_plain` jest saltem w derywacji `base_key`, każda wiadomość ma unikalny `base_key` i unikalne klucze AEAD dla body i headers.

**Odporność na nonce reuse.** Użyto AES-256-GCM-SIV zamiast AES-256-GCM. Konstrukcja SIV toleruje nonce reuse — efektem kolizji jest ujawnienie faktu, że dwie wiadomości pod tym samym kluczem są identyczne, ale nie klucz ani plaintext. Przy 96-bitowych losowych nonce, kolizja wymaga rzędu 2^48 zaszyfrowanych blobów pod tym samym kluczem AEAD, co jest nieosiągalne w praktyce i wymagałoby wielokrotnego użycia `base_key` (co się nie zdarza). Wybór SIV eliminuje katastroficzne następstwa reuse jako mechanizm defense-in-depth.

**Separacja body–headers.** Body i headers są szyfrowane pod różnymi kluczami, wyprowadzonymi z różnymi labelami. Podmiana lub zamiana `enc_body`/`enc_headers` między sobą lub ze zwykłym `enc_body` z innej wiadomości skutkuje błędem uwierzytelnienia AEAD — klucze nie pasują. Poprawnie odszyfrowane body i headers mają wspólne pochodzenie z tego samego `base_key`, więc są ze sobą implicitnie powiązane.

**Weryfikacja integralności przed decapsulacją.** W `decrypt_kyber_seed`, `SHA256(ct_kem)` jest weryfikowane względem zapisanego salta w blobie *zanim* nastąpi decapsulacja. Zapobiega to użyciu blobu jako wyroczni decapsulacji dla ciphertextów wybranych przez atakującego (przynajmniej na poziomie deterministycznego filtrowania). Czy ten filtr jest wystarczający wobec atakującego adaptacyjnego, wymaga weryfikacji w konkretnym modelu bezpieczeństwa ML-KEM. Oznacza to też, że uszkodzenie `ct_kem` jest wykrywane przed wywołaniem kodu ML-KEM w C.

## Założenia

KyberBox przyjmuje następujące założenia, których dotrzymanie należy do wywołującego:

**Klucze publiczne odbiorcy są autentyczne.** KyberBox nie weryfikuje, że `peer_pub_x` ani `peer_k_pub` należą do zamierzonego odbiorcy. Podstawienie tych kluczy przez atakującego powoduje zaszyfrowanie wiadomości dla złej strony. W `session.rs` klucze te pochodzą z zapisanego stanu kontaktu; ich autentyczność jest odpowiedzialnością warstwy invite/handshake.

**String kontekstu jest unikalny dla tego użycia.** Separacja domenowa przez `ctx` jest skuteczna tylko jeśli różne protokoły lub użycia KyberBox stosują różne wartości. Aktualnie jedynym wywołującym jest `session.rs` z `"lithiumd/e2e-msg/v1"`. Gdyby KyberBox był ponownie użyty z tym samym `ctx` w innym kontekście, możliwe byłyby ataki krzyżowe.

**Wywołujący poprawnie przekazuje `from_x_pub` do wywołania deszyfrowania.** KyberBox nie weryfikuje relacji między kluczem X25519 przekazanym do `decrypt` a żadną wartością w `seed_enc`. Po stronie deszyfrowania `decrypt_with_privs` w `session.rs` odczytuje `from_x_pub` z ramki wire i przekazuje go jako `peer_pub_x`. Modyfikacja `from_x_pub` w transporcie powoduje, że ECDH produkuje błędny shared secret, co skutkuje błędem deszyfrowania AEAD — atak więc nie przechodzi — ale wykrycie odbywa się przez błąd AEAD, nie przez explicite sprawdzenie tożsamości wewnątrz KyberBox.

**CSRNG jest niezakompromitowany.** `seed_plain`, efemeryczny klucz X25519 i wszystkie nonce AEAD pochodzą z `SysRng`. Jakikolwiek bias lub przewidywalność systemowego generatora łamie świeżość klucza per wiadomość.

## Czego KyberBox nie gwarantuje

**Uwierzytelnienie nadawcy.** Nic w KyberBox nie wiąże szyfrogramu z konkretnym nadawcą. Każda strona, która zna `peer_k_pub` i `peer_pub_x` (lub przechwyci `from_x_pub` podczas transmisji), może wyprodukować prawidłowy `WirePayload`. W protokole Lithium uwierzytelnienie jest zapewniane zewnętrznie przez podwójny podpis Ed25519 + ML-DSA-87 nad plaintextem nagłówków i body, weryfikowany w `session.rs` przed zwróceniem odszyfrowanej treści.

**Ochrona przed replay (na poziomie KyberBox).** Zarejestrowany prawidłowy `WirePayload` może zostać ponownie przesłany do tego samego odbiorcy i AEAD zakończy się sukcesem — sam KyberBox nie wiąże szyfrogramu z żadnym licznikiem ani stanem, a klucz RX nie jest konsumowany przy deszyfrowaniu (lookup `self_get_rx_privs` to odczyt, nie usunięcie). Detekcję replay realizują dwie niezależne warstwy wyżej.

**Warstwa 1 — okno replay w `session.rs`.** Każdy nagłówek niesie monotonicznie rosnący licznik nadawcy `step` (część **podpisanego** nagłówka). Po weryfikacji podpisu, a przed jakąkolwiek mutacją stanu peera, `decrypt_with_privs` woła `peer_st.replay.check_and_record(hdr.step)` (`ReplayWindow`, `state.rs:117-145`). Jest to okno przesuwne (jak w IPsec/DTLS) szerokości 64: dokładny duplikat `step` albo `step`, który wypadł poniżej okna, jest odrzucany z `replayed_message_err()`. Okno **celowo toleruje reordering** różnych, jeszcze niewidzianych `step` w swoim zasięgu, bo warstwa kluczy RX i tak akceptuje wiadomości poza kolejnością. Kolejność operacji (podpis → replay → mutacja) jest istotna: sfałszowany `step` nie zatruje okna, a odrzucona powtórka nie zostawia częściowego stanu.

**Warstwa 2 — deduplikacja `msg_id` w warstwie przechowywania (defense-in-depth).** Każda wiadomość niesie w podpisanym nagłówku losowy `msg_id` (16 B); auto-fetch (`traffic.rs`) zapisuje ją przez `add_message` do tabeli z ograniczeniem `UNIQUE(msg_id)`. Powtórzony `msg_id` zwraca `Ok(false)` → element oznaczany `duplicate`, niezapisywany do historii i niepokazywany. Dodatkowo serwer kasuje wiadomość atomowo przy pierwszym pobraniu (one-time fetch), więc do realnego replay i tak potrzebny jest złośliwy serwer re-injektujący ramkę do skrzynki. Gdyby powtórka ominęła oba mechanizmy, ponowna deszyfracja ma efekty uboczne idempotentne: numery sekwencji i generacje przesuwają się wyłącznie w przód (brak regresji stanu).

**Forward secrecy na poziomie X25519 w obrębie jednej epoki ratchet.** Klucz X25519 odbiorcy (`rx_x_priv`) jest przechowywany aż do momentu, gdy odbiorca wyśle odpowiedź i nadawca zacznie używać nowego klucza. Wszystkie wiadomości wysłane do odbiorcy w tej epoce mają wspólny komponent X25519. Skompromitowanie `rx_x_priv` pozwala retroaktywnie odszyfrować komponent ECDH dla wszystkich wiadomości zaszyfrowanych dla tego klucza. Ścieżka ML-KEM nadal zapewnia separację per wiadomość (każda ma unikalny `seed_plain`), ale jeśli ML-KEM zostanie złamany, odzyskanie `rx_x_priv` pozwoliłoby odszyfrować wszystkie wiadomości z epoki.

**Explicite powiązanie między `seed_enc`, `enc_body` i `enc_headers`.** Trzy pola `WirePayload` to niezależnie uwierzytelnione blobs AEAD. Nie istnieje żaden wspólny MAC ani commitment obejmujący je wszystkie razem. Powiązanie jest implicite: `enc_body` i `enc_headers` są odszyfrowywalne tylko jeśli `seed_plain` zostanie poprawnie odzyskane z `seed_enc`, i tylko jeśli `seed_plain` jest tym samym, które użyto podczas szyfrowania. Podstawienie dowolnego pola z innej wiadomości powoduje błąd AEAD, ale jest to błąd AEAD, nie naruszenie protokołu wyższego poziomu, które odbiorca mógłby odróżnić od zwykłego uszkodzenia transmisji.

## Otwarte ryzyka i pytania do audytora

Skonsolidowane uzasadnienie samego kombinatora hybrydowego (porównanie z X-Wing i pytania
Q1–Q4 postawione wprost jako zakres dla audytora) znajduje się w [`combiner.md`](combiner.md).
Poniżej szczegółowe ryzyka na poziomie konstrukcji.

**HKDF bez salta w `derive_ecdh_key`.** Wywołanie to `HKDF-SHA256(IKM=ecdh_ss, salt=None, info=...)`. Zgodnie z RFC 5869 §2.2, brak salta powoduje, że HKDF-Extract używa klucza HMAC wypełnionego zerami o długości `HashLen`. Wynik X25519 jest wówczas traktowany bezpośrednio jako IKM. Wynik X25519 to 32-bajtowa wartość na grupie Curve25519 — nie jest jednostajnie losowy na pełnych 256 bitach (najwyższy bit jest zawsze 0, niskie bity są wyczyszczone przez clamping). To standardowa praktyka stosowana w wielu protokołach, ale audytor powinien zweryfikować, że konkretny dowód bezpieczeństwa obejmuje tę dystrybucję IKM.

**Przechowywanie klucza prywatnego X25519 jako raw seed przed clampingiem.** `random_x25519_keypair` zwraca i zapisuje `sk_seed` — 32 bajty przed clampingiem — nie sklamponowany skalar. Clamping jest aplikowany przy każdym użyciu przez `XStaticSecret::from(seed_array)`. Wzorzec jest poprawny i spójny wewnątrz bazy kodu, ale każdy przyszły kod, który bezpośrednio interpretowałby zapisane bajty jako skalar Curve25519, byłby błędny. Audytor powinien zweryfikować wszystkie miejsca użycia, żeby upewnić się, że klucz prywatny zawsze przechodzi przez `XStaticSecret::from()`.

**Kod C PQClean jest niezaudytowaną zewnętrzną zależnością.** Implementacja ML-KEM-1024 to referencyjny kod C PQClean, kompilowany przez FFI. Ścieżki AVX2 i NEON są włączone domyślnie. Zespół Lithium nie audytował tego kodu. Jakikolwiek side-channel czasowy, problem bezpieczeństwa pamięci lub niezgodność z FIPS 203 w kodzie PQClean byłyby dziedziczone. To standardowe ryzyko zależności, ale warto je odnotować explicite biorąc pod uwagę model zagrożeń.

**Brak explicite powiązania `from_x_pub` wewnątrz KyberBox (odchylenie D1 — patrz `combiner.md`).** Efemeryczny klucz publiczny X25519 nadawcy (`from_x_pub` w `WireV1`) jest używany jako `peer_pub_x` w wywołaniu `decrypt`, ale nie jest zawarty w żadnym info HKDF ani AAD żadnego AEAD wewnątrz kyberbox.rs. Modyfikacja `from_x_pub` w transporcie powoduje błąd AEAD (inne wyjście ECDH → inny `base_key`), więc aktywny atakujący nie może go po cichu podstawić. Jednak KyberBox sam z siebie nie wskazuje, *który* klucz publiczny był użyty — atrybucja wiadomości do konkretnego nadawcy leży po stronie wywołującego. W `session.rs` zapewnia to weryfikacja zewnętrznego podpisu. Istotne: w roli kombinatora `from_x_pub` to szyfrogram klasyczny (`ct_T`), który *oba* kombinatory IETF (`draft-irtf-cfrg-hybrid-kems`) wiążą jawnie w KDF, bo X25519 nie ma C2PRI; KyberBox wiąże go tylko implicite przez `ecdh_ss`. Tania naprawa: dodać `msg_x_pub` (i `ct_kem`) do `info` w derywacji `base_key`, co czyni z konstrukcji instancję UniversalCombinera.
## Podsumowanie

KyberBox to prosta hybrydowa konstrukcja KEM-DEM: ML-KEM-1024 enkapsuluje świeży 32-bajtowy seed, X25519 dostarcza drugi niezależny shared secret, oba są łączone przez HKDF w `base_key`, a body i headers są szyfrowane przez AES-256-GCM-SIV pod kluczami wyprowadzonymi z `base_key`. Schemat ma na celu osiągnięcie świeżości klucza per wiadomość przez losowy seed, hybrydowego bezpieczeństwa klasyczne/post-kwantowego przez kombinowaną derywację klucza i odporności na nonce reuse przez konstrukcję SIV — o ile użyte prymitywy spełniają standardowe założenia bezpieczeństwa.

Sam KyberBox nie zapewnia uwierzytelnienia, ochrony przed replay ani forward secrecy — te leżą w warstwach wyżej. Uwierzytelnienie (dual-sign) i forward secrecy realizuje warstwa sesji (`lithiumd/src/e2e/session.rs`). Ochrona przed replay jest **dwuwarstwowa**: przesuwne okno na podpisanym liczniku `step` w `session.rs` (`ReplayWindow`) oraz deduplikacja po `msg_id` z ograniczeniem `UNIQUE` w warstwie przechowywania (auto-fetch w `traffic.rs` + `add_message`), wsparta one-time fetch po stronie serwera.

Główne pozycje wymagające zewnętrznej walidacji to: implementacja C ML-KEM-1024 z PQClean, konwencja clampingu X25519 we wszystkich miejscach przechowywania i użycia kluczy oraz konkretne bezpieczeństwo HKDF-SHA256 z wynikiem X25519 jako IKM bez explicite salta.