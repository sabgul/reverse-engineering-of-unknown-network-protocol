# ISA-reverse-engineering
Vašou úlohou je:

- Zachytiť komunikáciu medzi poskytnutým serverom a klientom 
- Implementovať vlastný Wireshark dissector pre daný protokol
- Implementovať kompatibilného klienta pre daný protokol

### Upresnenie zadania:

#### 1. Zachytenie protokolovej komunikácie
   
K zadaniu projektu bude dodaný virtuálny stroj s referenčným klientom a serverom. Vhodným použitím klienta vygenerujte komunikáciu medzi klientom a serverom ktorú zachytíte pomocou nástroja Wireshark do PCAPu. Táto komunikácia bude slúžiť ako základ pre Vašu implementáciu. Formát protokolu popíšte do dokumentácie.

#### 2. Implementovanie Wireshark dissectoru

Podporu nástroja Wireshark pre sieťové protokoly je možné rozšíriť pomocou vlastných dissectorov implementovaných v jazyku C alebo Lua. Dissectory umožňujú prezentovať protokolové dáta v užívateľsky prívetivejšej forme.

Naštudujte si tvorbu dissectorov, napr. z Wireshark wiki ([1-3]). Implementuje dissector pre zachytený protokol. Detaily formátu dissectoru zvoľte podľa vlastného uváženia, cieľom je aby výsledná forma bola jasne pochopiteľná pre užívateľa. Návrh dissectoru dôkladne popíšte v dokumentácii.

#### 3. Implementovanie kompatibilného klienta

Na základe nadobudnutých znalostí o protokole naimplementuje kompatibilného klienta. Klient by mal byť schopný slúžiť ako "drop-in" náhrada referenčného klienta, ako vo formáte spustenia tak aj výstupu. Pri nejasnostiach sa riaďte chovaním referenčného klienta. Váš klient môže obsahovať pridanú funkcionalitu, mal by však byť striktne kompatibilný s referenčnou implementáciou. Dokumentácia bude obsahovať popis akýchkoľvek rozšírení, popisovať funkcionalitu referenčnej implementácie nie je nutné.

Klient bude implementovaný v jazykoch C/C++ a súčasťou riešenia bude Makefile ktorý po spustení vytvorí spustiteľného klienta s názvom client. Riešenie by malo byť preložiteľné a spustiteľné na dodanom virtuálnom stroji.

#### 4. Dokumentácia

Dokumentáciu je možné písať v jazykoch čeština, slovenčina alebo angličtina a vytvoriť v ľubovolnom nástroji (LaTeX, Microsoft Word, LibreOffice Writer, org-mode, Pandoc, ...), výsledkom však bude PDF súbor.
Obsahom dokumentácie bude analýza zachytenej komunikácie, popis protokolu, návrhu dissectoru a prípadných rozšírení klienta. Dokumentácia bude hodnotená nielen po technickej (obsahovej), ale aj po formálnej (jazykovej a prezentačnej) stránke. Všetky použité zdroje budú korektne citované v súlade s [4].

Odovzdanie projektu:

Projekt bude odovzdaný ako archív formátu tar bez komprimácie s názvom xlogin99.tar.
Archív bude obsahovať:
- dokumentáciu (manual.pdf)
- zachytenú komunikáciu (isa.pcap)
- dissector (isa.lua)
- Makefile
- zdrojové kódy klienta