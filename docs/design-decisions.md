# Decyzje projektowe (rejestr „dlaczego")

Warstwa ponad „co/jak" z [crypto-protocol.md](protocol/crypto-protocol.md): *dlaczego* główne wybory architektoniczne i kryptograficzne są takie, jakie są. Każdy wpis podaje decyzję, uzasadnienie, odrzucone alternatywy i koszt — żeby audytor i nowy kontrybutor nie musieli re-litygować raz podjętych decyzji. Priorytety, na które te decyzje odpowiadają, opisuje [security-model.md](security/security-model.md).

## 1. Hybryda klasyczna + post-kwantowa

**Decyzja.** Każdy KEM to X25519 + ML-KEM-1024, każdy podpis to Ed25519 + ML-DSA-87; sekrety łączone tak, że trzeba złamać **oba** schematy.

**Dlaczego.** Chroni przed „harvest-now-decrypt-later" (przeciwnik kwantowy) nie rezygnując z dojrzałego bezpieczeństwa klasycznego. Gdyby któryś schemat PQ okazał się wadliwy kryptoanalitycznie, klasyczny nadal trzyma — i odwrotnie.

**Odrzucone.** Czysto klasyczny (podatny na kwant); czysto PQ (młode schematy, większe ryzyko wad implementacji i kryptoanalizy).

**Koszt.** Większe klucze i szyfrogramy (ML-KEM 1568 B, ML-DSA 2592 B), wolniejsze operacje, zależność od kodu C PQClean (niezaudytowana — patrz [threat-model.md](security/threat-model.md) #8).

## 2. OPAQUE zamiast przechowywanego hasha hasła / SRP

**Decyzja.** Uwierzytelnianie kont przez OPAQUE (aPAKE, `opaque-ke 4.0.1`, ristretto255 + Argon2 jako KSF).

**Dlaczego.** Serwer **nigdy** nie widzi hasła ani jego hasha — nie ma czego ukraść z DB ani podsłuchać; offline-crack bazy jest niemożliwy (brak weryfikatora hasła po stronie serwera). Dodatkowo `export_key` z OPAQUE owija `server_dek`, wiążąc dostęp do DEK z poprawnym hasłem.

**Odrzucone.** Hash hasła (PHC Argon2) w DB — kradzież DB umożliwia offline crack; SRP — starszy, brak PQ-friendly właściwości i więcej pułapek implementacyjnych; hand-rolled PAKE — duża bespoke surface.

**Koszt.** Dwufazowy handshake (`start`/`finish`) zamiast jednego żądania; zależność od biblioteki OPAQUE.

## 3. AES-256-GCM-SIV jako jedyny AEAD

**Decyzja.** Cały AEAD to AES-256-GCM-SIV (nonce-misuse-resistant, SIV).

**Dlaczego.** W systemie jest wiele miejsc, gdzie nonce pochodzi z derywacji lub struktury (np. nonce z HKDF, deterministyczne `id_enc`). SIV degraduje się łagodnie przy powtórzeniu nonce — ujawnia jedynie równość plaintextu, nie klucz — zamiast katastrofy jak zwykły GCM. To „szelka bezpieczeństwa" przeciw błędom w zarządzaniu nonce.

**Odrzucone.** AES-GCM (katastrofalny przy nonce-reuse); ChaCha20-Poly1305 (również wrażliwy na nonce-reuse, brak SIV).

**Koszt.** Deterministyczność (ten sam plaintext+nonce+klucz → ten sam szyfrogram) — świadomie wykorzystywana (np. `id_enc`), ale wymaga uwagi tam, gdzie potrzebna losowość (KyberBox używa świeżych nonce per wiadomość).

## 4. Adresowanie skrzynek per kontakt (anonimowe mailboxy)

**Decyzja.** Serwer nigdy nie routuje po tożsamości; adres skrzynki = `HKDF(ECDH(out_priv, in_pub), salt=cid||cid||gen, "lithium/mbox/address/v1")` — pseudolosowe 32 B liczone niezależnie przez obie strony.

**Dlaczego.** Serwer widzi wyłącznie nieprzejrzysty adres — nie powiąże nadawcy z odbiorcą ani nie zbuduje grafu społecznego. Rotacja klucza nadawczego co 32 wysłania dodatkowo rozprasza adresy.

**Odrzucone.** Routing po user-id/handlerze (serwer zna graf); jedna stała skrzynka per użytkownik (linkowalna w czasie).

**Koszt.** Złożoność (generacje, fetch w oknie −2..+1), brak prostego „inbox" po stronie serwera; klient sam liczy adresy.

## 5. Commit-reveal sprzężony z krótkim SAS

**Decyzja.** Parowanie to jednostronny commit-reveal (4 komunikaty OOB), a weryfikacja tożsamości to 6-symbolowy SAS (alfabet 64 → 36 bitów).

**Dlaczego.** Krótki SAS (wygodny do porównania głosem) jest bezpieczny **wyłącznie** dzięki commit-reveal — bez niego MITM mógłby offline grindować własne klucze pod SAS ofiary (~2^18 ewaluacji, trywialne na GPU). Commit-reveal zmusza atakującego do zafiksowania kluczy zanim druga strona ujawni kod → jeden ślepy strzał 2^-36 na całą ceremonię.

**Odrzucone.** Długi SAS bez commit-reveal (niewygodny w porównaniu głosowym); commit-reveal bez SAS (brak ludzkiej weryfikacji anty-MITM).

**Koszt.** **Niezmiennik sprzężenia**: skrócenie SAS *albo* usunięcie commit-reveal w izolacji ponownie otwiera offline-grind. Obu mechanizmów nie wolno zmieniać niezależnie (patrz [crypto-protocol.md](protocol/crypto-protocol.md), „Niezmiennik sprzężenia").

## 6. Constant-rate cover traffic + brak manual fetch

**Decyzja.** Daemon wysyła i pobiera w stałej kadencji; realne wysyłki jadą w slotach, dummy wypełniają luki do self-loop cover-skrzynki; nie ma komendy manual fetch — odbiór jest automatyczny.

**Dlaczego.** Ukrywa przed obserwatorem sieci i serwerem czas oraz wolumen realnej komunikacji — bez stałej stopy samo „kiedy" i „ile" zdradza aktywność. Manual fetch tworzyłby obserwowalny wzorzec ruchu.

**Odrzucone.** Wysyłka/fetch na żądanie (wzorzec ruchu = metadane); brak cover traffic (wyciek timingu).

**Koszt.** Stała szerokość pasma nawet przy braku ruchu; throughput realnych wysyłek capowany stopą; latencja odbioru ograniczona kadencją.

## 7. Dwuczynnikowy DEK (hasło + server_dek)

**Decyzja.** `db_dek = HKDF(combined_root)`, gdzie `combined_root` łączy `password_root` (z hasła danych) i `server_dek` (z serwera) — oba wymagane.

**Dlaczego.** Rozdziela dwa zagrożenia: sama kradzież dysku (nawet z hasłem) nie wystarcza bez współpracy serwera, a sam serwer nigdy nie ma hasła. Odczyt lokalnych danych wymaga obu niezależnych czynników.

**Odrzucone.** DEK tylko z hasła (kradzież dysku + brute-force hasła = dane); DEK tylko z serwera (przejęcie serwera = dane).

**Koszt.** Brak dostępu offline-only do bazy — odblokowanie storage wymaga sesji z serwerem, by pobrać `server_dek` (patrz [key-hierarchy.md](security/key-hierarchy.md)).

## 8. Pieczętowanie Master Key serwera w TPM

**Decyzja.** Domyślnie `TpmMkProvider` — MK serwera zapieczętowany jako obiekt KEYEDHASH pod parentem ECC P-256 derywowanym deterministycznie z owner seed (parent nigdy nie persystowany).

**Dlaczego.** MK serwera nie leży w plaintext na dysku w konfiguracji domyślnej — kradzież obrazu dysku serwera nie daje MK bez tego konkretnego TPM.

**Odrzucone.** MK w pliku (plaintext na dysku — dostępny tylko jako fallback `LITHIUM_MK_PROVIDER=plain`); zewnętrzny KMS (dodatkowa zależność i zaufanie).

**Koszt.** Wymóg TPM 2.0 na hoście; build z feature `tpm` (`tss-esapi`); fallback plaintext degraduje gwarancję.

## 9. Deterministyczne szyfrowanie identyfikatora użytkownika

**Decyzja.** `id_enc = AES-256-GCM-SIV(uuid_v5(handler), db_dek, nonce=HKDF(uuid, …), aad="user-idenc/v1")` — deterministyczne, by ten sam handler zawsze dawał ten sam wiersz.

**Dlaczego.** Umożliwia indeksowane wyszukiwanie użytkownika po handlerze **bez** przechowywania jawnego handlera ani osobnej tablicy mapowań — serwer nie ma plaintextu handlera.

**Odrzucone.** Jawny handler w DB (wyciek tożsamości); losowe szyfrowanie + osobny indeks (indeks przechowywałby de facto plaintext).

**Koszt (świadomy).** Obserwowalność równości — między snapshotami DB widać, że dwa wiersze to ten sam użytkownik (jeden wiersz per nick). Nigdy „kto", tylko „czy istnieje / czy to samo". Patrz [security-model.md](security/security-model.md).

## 10. Utrata materiału klucza zamiast wektorów odzysku

**Decyzja.** Brak recovery hasła i kluczy, brak backupu seedów; utrata = utrata danych.

**Dlaczego.** Każdy wektor odzysku (escrow, pytania pomocnicze, recovery codes na serwerze) jest powierzchnią ataku i celem przymusu prawnego — sprzeczny z priorytetem „operator matematycznie nie może ujawnić treści". Lithium świadomie przedkłada utratę nad odzysk.

**Odrzucone.** Key escrow, social recovery, server-side backup — wszystkie osłabiają model zaufania.

**Koszt.** Błąd użytkownika (zapomniane hasło, utracone urządzenie) jest nieodwracalny; wyższy ciężar UX i edukacji.
