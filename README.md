# elte-ik-msc-p4
Minimális TCP szerver implementálása P4 nyelven.

# Minimális TCP Handshake P4 Switch

Ez a projekt egy **P4 switch-t** implementál, amely képes kezelni a TCP **SYN** és **SYN-ACK** csomagokat, és válaszol egy minimális, statikus payload-ot tartalmazó **PSH-ACK** csomaggal. A célja a TCP handshake minimális logikájának szimulálása egy P4-es switch-en keresztül.

## 🚀 Projekt célja

A projekt célja, hogy egy egyszerű **TCP handshake** logikát implementáljon P4-ben, amely:

- Felismeri a **TCP SYN** csomagot
- **SYN-ACK** választ küld vissza
- **PSH-ACK** csomagban **dummy válasz** (pl. `"Hi from switch!"`) küld vissza, mint statikus adat

A projekt az alábbiakból áll:

1. **P4 program** a TCP handshake kezeléséhez
2. **Mininet topológia** a virtuális hálózati környezethez
3. **Scapy tesztelés** a válaszok automatikus ellenőrzésére


## 🖧 Hálózati topológia:
```
     +--------+           +--------+           +--------+
     |        |  h1-eth0  |        |  s1-eth1   |        |
     |  Host  |-----------|  s1    |------------|  Host  |
     |   h1   |           | switch |            |   h2   |
     +--------+           +--------+           +--------+
      IP: 10.0.0.1                           IP: 10.0.0.2
```

    - h1 küldi a TCP SYN-t 10.0.0.2:12345 címre (ez a "szerver" port).

    - s1 P4 switch felismeri a SYN-t, válaszol SYN-ACK-kal, srcPort=12345, dstPort=1234

    - h1 válaszol PSH-ACK csomaggal (adatküldés).

    - s1 újra válaszol dummy PSH-ACK-kal.

## 📬 IP-k és Portok

### Scapy teszt:

dst_ip = "10.0.0.2"     # h2 IP-je – DE a valóságban a switch küld választ

dst_port = 12345        # "szerver" port (switch oldalon)

src_port = 1234         # "kliens" port

### P4:

hdr.ipv4.srcAddr = 0x0a000002; // 10.0.0.2 ← válaszként szerepel

hdr.tcp.srcPort = 12345;       // "szerver" port

## 🧰 Követelmények

- **P4C** (P4 Compiler) telepítése
- **Mininet** telepítése
- **Scapy** Python könyvtár
- **xterm** (opcionális) a teszt futtatásához
- **Python3** a teszteléshez

## ⚙️ Telepítés és futtatás

1. **A projekt letöltése**

    Klónozd a repository-t:

    ```bash
    git clone https://github.com/username/tcp-p4-handshake.git
    cd tcp-p4-handshake
    ```

2. **P4 program fordítása**

    Először is, le kell fordítanod a P4 programot:

    ```bash
    p4c --target bmv2 --arch v1model -o tcp_dummy.json main.p4
    ```

3. **Mininet topológia indítása**

    Használjuk a `tcp_topo.py` scriptet a Mininet hálózat elindításához. Ezt a fájlt futtathatod a következőképpen:

    ```bash
    sudo python3 tcp_topo.py
    ```

4. **Szabályok betöltése**

    A szabályokat a `commands.txt` fájlba mentheted, és betöltheted őket a Mininet switch-be:

    ```bash
    echo "
    table_add tcp_table send_synack 0x02 =>
    table_add tcp_table send_dummy_response 0x18 =>
    " > commands.txt
    ```

5. **Tesztelés Scapy-val**

    A **Scapy** segítségével tudod tesztelni a TCP handshake működését. Futtasd a következő szkriptet a `h1` hostról:

    ```bash
    python3 scapy_tcp_handshake_test.py
    ```

    A script automatikusan küldi el a TCP SYN csomagot, várja a SYN-ACK válaszokat, majd PSH-ACK válasz küldésére figyel.

6. **Automatikus szkript futtatása** (opcionális)

    A projekthez tartozik egy **automatikus bash szkript** is, amely egy lépésben végrehajtja az összes feladatot: a fordítást, a Mininet indítást, a szabályok betöltését és a teszt futtatását. Ehhez egyszerűen futtasd a következőt:

    ```bash
    ./run_all.sh
    ```

    A szkript mindent elvégez, és megjeleníti az eredményeket.

## 🧑‍💻 Tesztelés és ellenőrzés

A teszt a **Scapy** Python könyvtárral történik. A `scapy_tcp_handshake_test.py` script:

- TCP SYN csomagot küld
- Várakozik SYN-ACK válaszra
- PSH-ACK válasz küldése után ellenőrzi a dummy válasz helyességét

A válaszok a szkript futtatásakor automatikusan megjelennek, és ha minden rendben van, a következő üzenet jelenik meg:



## 🔧 Bővítési lehetőségek

- **Dinamikus payload generálás**: Ahelyett, hogy statikus szöveget küldenénk, implementálható egy egyszerű logika, amely dinamikusan generálja a payload-ot.
- **Bonyolultabb TCP logika**: Ha szükséges, a P4 program bővíthető más TCP szempontokkal, mint a háromutas handshake teljes szimulálása vagy a TCP adatkezelés.
- **Továbbfejlesztett tesztelés**: A Scapy tesztelés automatizálható további szempontok szerint, például TCP háromutas handshake teljes körű szimulálásával.

## 📝 Megjegyzések

Ez a projekt egy egyszerű példát nyújt a **TCP handshake** minimális logikájának implementálására a P4-es nyelvben. Az alapvető cél az, hogy a P4 program képes legyen a TCP protokoll alapvető működését szimulálni.
