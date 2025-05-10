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
     +--------+                     +--------+ 
     |        |        h1-eth0      |        |
     |  Host  |---------------------|   s1   |
     |   h1   |                     | switch |
     +--------+                     +--------+ 
      IP: 10.0.0.1                   10.0.0.2
      MAC:00:00:00:00:00:01     00:00:00:00:02:00
```

    - h1 küldi a TCP SYN-t 10.0.0.2:12345 címre (ez a "szerver" port).

    - s1 P4 switch felismeri a SYN-t, válaszol SYN-ACK-kal, srcPort=12345, dstPort=12345

    - h1 válaszol PSH-ACK csomaggal (adatküldés).

    - s1 újra válaszol dummy PSH-ACK-kal.

## 📬 IP-k és Portok

### Scapy teszt:

dst_ip = "10.0.0.2"     # s1 IP-je – A switch küld választ

dst_port = 12345        # "szerver" port (switch oldalon)

src_port = 12345         # "kliens" port

## 🧰 Követelmények

- **P4C** (P4 Compiler) telepítése
- **Mininet** telepítése
- **Scapy** Python könyvtár
- **Python3** a teszteléshez

## ⚙️ Telepítés és futtatás

1. **A projekt letöltése**

    Klónozd a repository-t:

    ```bash
    git clone https://github.com/username/tcp-p4-handshake.git
    cd tcp-p4-handshake
    ```

2. **P4 program fordítása, topológia indítása, Szabályok betöltése**

    A projekthez tartozik egy **automatikus bash szkript** is, amely egy lépésben végrehajtja az összes feladatot: a fordítást, a Mininet indítást, a szabályok betöltését és a teszt futtatását. Ehhez egyszerűen futtasd a következőt (**Részletekért lásd a tcp_topo.py fájlt**):

    ```bash
    ./run_all.sh
    ```

3. **Tesztelés Scapy-val**

    A **Scapy** segítségével tudod tesztelni a TCP handshake működését. Futtasd a következő szkriptet a `h1` hostról:

    ```bash
    mininet> h1 python3 tcp_test.py
    ```

    A script automatikusan küldi el a TCP SYN csomagot, várja a SYN-ACK válaszokat, majd PSH-ACK válasz küldésére figyel.

## 🧑‍💻 Tesztelés és ellenőrzés

A teszt a **Scapy** Python könyvtárral történik. A `tcp_test.py` script:

- TCP SYN csomagot küld
- Várakozik SYN-ACK válaszra
- PSH-ACK válasz küldése után ellenőrzi a dummy válasz helyességét

A válaszok a szkript futtatásakor automatikusan megjelennek, és ha minden rendben van, a következő üzenet jelenik meg:

## 📝 Kimenetek:
A program automatikusan ment minden csomagot ami be és ki érkezik a switch-ből. EzeK A log mappában vannak-
Hasznos lehet élőben is figyelni a kimenetet az alábbi parancssal:

```bash
sudo tcpdump -i s1-eth1 -nn -v
```


## 🔧 Jelenlegi állapot:
**HIBA:** Jelenleg a program valamiért az [S] csomag helyes felismerés után lezárja a kapcsolatot [R]. Oka eggyenlőre ismeretlen.
```

21:21:49.849158 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 40)
    10.0.0.1.12345 > 10.0.0.2.12345: Flags [S], cksum 0x1b0a (correct), seq 100, win 8192, length 0
21:21:49.849231 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    10.0.0.2.12345 > 10.0.0.1.12345: Flags [R.], cksum 0x3af7 (correct), seq 0, ack 101, win 0, length 0
21:21:49.850893 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 40)
    10.0.0.2.12345 > 10.0.0.1.12345: Flags [S.], cksum 0x1af9 (correct), seq 0, ack 101, win 8192, length 0
21:21:49.850956 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    10.0.0.1.12345 > 10.0.0.2.12345: Flags [R], cksum 0x3b07 (correct), seq 101, win 0, length 0
21:21:49.850987 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    10.0.0.2.12345 > 10.0.0.1.12345: Flags [R.], cksum 0x3af7 (correct), seq 0, ack 1, win 0, length 0
21:21:49.852881 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    10.0.0.1.12345 > 10.0.0.2.12345: Flags [R], cksum 0x3b07 (correct), seq 101, win 0, length 0

```

## 📝 Megjegyzések

Ez a projekt egy egyszerű példát nyújt a **TCP handshake** minimális logikájának implementálására a P4-es nyelvben. Az alapvető cél az, hogy a P4 program képes legyen a TCP protokoll alapvető működését szimulálni.
