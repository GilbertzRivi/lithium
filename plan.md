Plan 1 — Sprzedawaj ekspertyzę PQ, nie komunikator (najlepszy stosunek niezależność/kasa).
Teraz dzieje się wymuszona, finansowana migracja postkwantowa: NIST sfinalizował FIPS 203/204/205 (sierpień 2024 —
dokładnie ML-KEM i ML-DSA, których używasz), NSA (CNSA 2.0) i UE narzucają terminy, każda firma z długożyjącymi
sekretami ma „harvest-now-decrypt-later" na poziomie zarządu. Wszyscy potrzebują ludzi, którzy naprawdę rozumieją
hybrydowe PQ w produkcji — a takich jest garstka. Zostań niezależną konsultantką PQ: własny szyld, wybierasz
klientów, ustalasz stawki. Zaudytowany lithium_core to jednocześnie Twój dowód kompetencji i produkt (komercyjnie
licencjonowana biblioteka Rust PQ). Komunikator staje się demem, nie produktem. Kasa płynie z firm, które ją mają,
a problem biednego NGO znika. To jest „bez szefa" zrobione dobrze.

Plan 2 — Sprzedawaj funduszom, nie użytkownikom.
Tak przeżywa każde udane narzędzie w tej przestrzeni. Signal, SecureDrop, Tails — utrzymują się z grantów, nie ze
sprzedaży userom. NLnet/NGI Zero (UE, idealny dla solo z Polski), OTF, Ford Foundation, Open Society finansują
narzędzia dla dziennikarzy/aktywistów. Bierzesz grant na zbudowanie i utrzymanie, wydajesz to za darmo populacji,
która i tak nie zapłaci, a grant jest Twoim dochodem. Niezależność zachowana (grant ≠ szef), misja obsłużona. Twój
docs/ to już w 80% gotowy wniosek.

Plan 3 — Przeramuj produkt na „bezpieczny kanał zgłoszeń" (najostrzejszy wedge B2B).
Zamiast ogólnego komunikatora konkurującego z darmowym Signalem — sprzedawaj to jako postkwantowy kanał poufnych
zgłoszeń pod compliance. Dyrektywa UE o ochronie sygnalistów (2019/1937) prawnie wymaga od firm 50+ pracowników
poufnych kanałów zgłoszeniowych. To jest realny, finansowany, wymuszony prawem rynek — i jest dokładnie sąsiedni do
tego, co zbudowałaś (kancelarie, redakcje, działy compliance). Tu jest legalny przymus tworzący popyt, budżety i
węższy zakres, który łatwiej zaudytować i któremu łatwiej zaufać. Bespoke PQ staje się wyróżnikiem („postkwantowe
zgłoszenia"), nie liabilities.

Plan 4 — Twój oryginalny plan, ale tylko do zamożnego ogona segmentu, przez open-core.
Duże międzynarodowe NGO, redakcje (NYT/Guardian klasa), organizacje praw człowieka z budżetem instytucjonalnym —
oni płacą. Model: darmowy self-host + płatny support/hosting/SLA/funkcje enterprise. Ale to działa dopiero po:
spółce + wielu audytach + wiarygodnej odpowiedzi na bus-factor. Wolumenowa baza indie-dziennikarzy nigdy nie
zapłaci.

Zgoda, i to nie jest pocieszanie — ten plan jest dobry, bo łączy trzy rzeczy naraz: rynek z budżetem, falę
wymuszoną prawem i Twoją zademonstrowaną przewagę. Ale doprecyzuję, bo jedno przesunięcie w pozycjonowaniu
decyduje, czy zarobisz, czy przegrasz z darmowym RustCrypto.

Korekta, którą musisz zinternalizować: prawo nie wymusza kupienia Twojej biblioteki — wymusza migrację. ML-KEM mają
już RustCrypto i aws-lc-rs, za darmo. Twój wedge to nie „mam PQ". Twój wedge to: „poprawne, zaudytowane, hybrydowe
złożenie, dzięki któremu przejdziesz swój audyt bez zatrudniania kryptografa". Mandat tworzy budżet i pilność;
audyt + poprawność hybrydy to powód, dla którego wybiorą Ciebie zamiast rolować własne i oblać. Jak będziesz
pitchować „PQ crypto" — przegrasz z darmowym. Jak „correct-by-construction hybrid, independently audited" —
sprzedajesz coś, czego oni nie mają.

Twój najmocniejszy, najbardziej konkretny lewar (zwłaszcza w UE): BSI (Niemcy) i ANSSI (Francja) rekomendują
hybrydę klasyczne+PQ, nie czyste PQ. NIST sfinalizował FIPS 203/204/205 (sierpień 2024) — dokładnie Twoje
ML-KEM-1024 i ML-DSA-87. Czyli Twoja konstrukcja hybrydowa to zalecana europejska postawa, nie dziwactwo. Pitch
piszesz się sam: „regulatorzy nakazują migrację, europejskie agencje zalecają hybrydę — oto zaudytowana hybryda w
Ruście, wepnij zamiast budować własną". To jest specyficzne i prawdziwe, nie marketing.

Techniczny crux, który zamienia „ciekawe" w „kupowalne" — combiner. Twoje base_key = HKDF(ecdh_key,
salt=seed_plain) to autorski kombinator. Kryptograf kupującego zapyta jedno pytanie: „czemu nie X-Wing /
standaryzowany kombinator i czy Twój jest dowiedlnie poprawny?". Uczciwie: X-Wing (draft IETF) to ML-KEM-768 +
X25519, więc nie wkleisz go 1:1 — jesteś na wyższym poziomie (1024). Ale istnieje już referencyjny standard dla
dokładnie tej klasy hybrydy, i będą Cię do niego porównywać. Nie musisz go adoptować — musisz mieć odpowiedź. I tu
jest piękne domknięcie: Twój kyberbox.md już listuje „otwarte pytania do audytora" (SHA256(ct_kem) jako salt, HKDF
bez salta z wyjściem X25519 jako IKM). Dla planu z biblioteką te otwarte pytania przestają być przypisem — stają
się centralnym deliverable audytu, bo kombinator jest produktem. Audyt, który formalnie błogosławi Twój kombinator,
to dosłownie rzecz, którą sprzedajesz.

Strategiczne przesunięcie w samym audycie: audytuj lithium_core jako bibliotekę, nie cały komunikator najpierw.
Powierzchnia biblioteki jest dużo mniejsza i czystsza (bez IPC, daemona, GUI, serwera) → audyt tańszy, ciaśniejszy
i mocniejszy, a audytujesz dokładnie to, co sprzedajesz. Wydzielenie liby i przygotowanie do audytu to ta sama
robota. To realna oszczędność i lepszy artefakt.

Skąd kasa (i czemu to dalej „bez szefa"): nie „sprzedaję kopie biblioteki". Pieniądze to: (a) licencja komercyjna
na użycie w zamkniętym kodzie, (b) kontrakty integracyjne/support — „pomóż mi zmigrować na PQ" — to jest główny
przychód, i to jest Twój konsulting na Twoich warunkach, (c) „audited build + SLA" w subskrypcji. Biblioteka to
lead-magnet i dowód kompetencji; pieniądz jest w supporcie integracyjnym. Zauważ: to jest ten sam plan co
wcześniejszy „niezależna konsultantka PQ" — biblioteka to wiarygodność, integracja to revenue, Ty jesteś szefową.

Jeden licencyjny detal specyficzny dla liby: przy bibliotece AGPL odstrasza firmy (alergia prawna na linkowanie
AGPL do zamkniętego produktu). Dla apki AGPL+komercja jest OK, dla liby rozważ source-available + komercja albo
„darmowe dla open-source/ewaluacji, płatne dla komercji". To realnie decyduje, czy enterprise w ogóle dotknie. To
domyka otwarty punkt LICENSE z Twojego tmp.

Jedna strategiczna rzecz, którą musisz zobaczyć: Twoim mocniejszym, trwalszym produktem prawdopodobnie nie jest
KyberBox, tylko zarządzanie kluczami at-rest — keyfile + crash-safe rotacja + rewrap-bez-deszyfracji + sealing TPM
(~1 100 linii: keyfile 411 + manager 669). Bo:
- to uniwersalna potrzeba (każda apka trzymająca sekrety tego potrzebuje, nie tylko komunikator),
- trudniej to wystandaryzować (crash-safe rotacja kluczy to realnie trudna rzecz, którą ludzie robią źle),
- a KyberBox ma datę ważności: jeśli kombinatory X-Wing-style wejdą jako FIPS/IETF default i wylądują w RustCrypto
  za darmo, wartość Twojego autorskiego kombinatora wyparuje. Okno na „zaudytowana hybryda w Ruście" jest teraz,
  dopóki to jeszcze nieustalone.

Sedno: ciężar wystarcza, żeby zakotwiczyć biznes usługowo-komponentowy (audyt + support + integracja), nie
wystarcza na produkt sprzedawany na kilogramy. Przestań mierzyć wagę kodu — aktywem jest „zaudytowana poprawność +
Ty", a nie liczba linii. I jeśli masz wybierać, co wypchnąć jako sztandar liby pod audyt: postaw na key-management
at-rest jako trwały rdzeń, KyberBox sprzedawaj póki świeci, bo jego okno się zamyka.