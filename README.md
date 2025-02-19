# RL-Project1
 Switch Implementation

Descriere

Acest proiect implementează un switch virtual în Python, capabil să gestioneze
tabele CAM, VLAN-uri și algoritmul Spanning Tree Protocol (STP). Switch-ul
poate fi utilizat pentru testare într-o topologie virtuală.


Inițializare topologie virtuală

Pentru a configura topologia virtuală și a porni switch-urile, rulați următoarea comandă:
sudo python3 checker/topo.py

Aceasta va deschide mai multe terminale, fiecare reprezentând un host sau un switch.
Pornirea manuală a unui switch

Pentru a porni manual un switch, utilizați comanda:
make run_switch SWITCH_ID=X
unde X este ID-ul switch-ului (0, 1 sau 2).


Funcționalități

1. Tabela de Comutare (CAM Table)
Switch-ul folosește o tabelă CAM (Content Addressable Memory) pentru a mapa adresele MAC la porturile aferente:
Dacă destinația este unicast și se află în tabelă, pachetul este trimis pe portul corespunzător.
Dacă destinația nu este cunoscută, pachetul este transmis pe toate porturile (exceptând cel de recepție).
Dacă destinația este broadcast (ff.ff.ff.ff.ff.ff), pachetul este trimis pe toate porturile, exceptând sursa.

2. VLAN (Virtual Local Area Network)
Pentru gestionarea VLAN-urilor, switch-ul:
Stochează într-un dicționar tipul VLAN pentru fiecare port (access sau trunk).
Elimină sau adaugă tag-ul 802.1Q în funcție de tipul de port și VLAN-ul asociat.
Filtrează pachetele pe baza identificatorului VLAN.

3. Spanning Tree Protocol (STP)
Implementarea STP previne buclele în rețea prin:
Menținerea unui dicționar cu starea porturilor (listening sau blocking).
Trimiterea de mesaje BPDU la fiecare secundă de către root bridge.
Ajustarea root bridge-ului și a stării porturilor în funcție de BPDU primite.
Asigurarea că doar porturile listening pot transmite date.


Structura Codului

Switch: Clasa principală care gestionează tabelele CAM, VLAN și STP.
VLAN: Clasă auxiliară care definește un VLAN cu nume, ID și stare.
parse_ethernet_header(): Funcție pentru parsarea header-ului Ethernet.
vlan_switch(): Funcție care aplică regulile de forwarding pe baza VLAN-urilor.
receive_bpdu(), send_bpdu(), send_bdpu_every_sec(): Funcții pentru gestionarea mesajelor BPDU și STP.
main(): Punctul de intrare al programului, care inițializează switch-ul și gestionează fluxul pachetelor.

