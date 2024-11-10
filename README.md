1 2 3
# Implementare Switch

## Forwarding (Tabela de comutare)
La primirea cadrului Ethernet, switch-ul aplica algoritmul descris in cerinta pentru a lega o adresa MAC de un port. Se introduce in tabela de comutare (mac_table) interfata pe care a sosit cadrul.
Daca nu exista o intrare pentru adresa MAC destinatie, se va face broadcast pe toate celelalte porturi.

## VLAN
Pentru acest task am folosit dictionarul port_config pentru a pastra vlan-ul fiecarui port de pe switch.
La primirea unui cadru:
    - Se trimite mai departe cu header-ul 802.1Q daca se transmite pe un port de tip trunk,
    - Se trimite fara header-ul 802.1Q daca se transmite pe un port de tip access.

## STP (Spanning Tree Protocol)
Vom trimite pachete de tip BPDU (Bridge Protocol Data Units) la fiecare secunda, folosind un thread separat care apeleaza functia send_bpdu_every_sec. Aceasta functie verifica daca suntem root bridge,
 construieste pachetul BPDU si il transmite pe porturile de tip trunk.
Pachetele sunt construite cu ajutorul functiei struct.pack din Python, unde sunt setate campurile de root_bridge_id, root_path_cost, sender_bridge_id, celelalte fiind puse pe 0.
Functia de primire a pachetelor de tip BPDU este asemanatoare cu cea prezentata in enuntul temei, dar facand abstractie de porturile "Designated".
In urma implementarii acestui protocol, se verifica la transmiterea pachetelor daca porturile sunt pe "LISTENING".


