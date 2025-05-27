from scapy.all import *

# === KONFIGURÁCIÓ ===
DST_IP = "10.0.0.2"
DST_PORT = 1010
SRC_IP = "10.0.0.1"
SRC_PORT = 1175
CLIENT_SEQ = 100
IFACE = "h1-eth0"   # Mininet host interface!

# === SZÉP BANNER ===
def print_banner():
    print("\n" + "="*50)
    print("    P4 TCP HANDSHAKE & DUMMY VÁLASZ TESZT")
    print("="*50 + "\n")

def print_step(msg):
    print("\n" + "-"*40)
    print(f"[{msg}]")
    print("-"*40)

def main():
    print_banner()
    ip = IP(src=SRC_IP, dst=DST_IP)

    # 1. SYN küldése
    print_step("1. SYN küldése a switch felé")
    syn = TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=CLIENT_SEQ)
    synack_pkt = sr1(ip/syn, iface=IFACE, timeout=2, verbose=0)
    if not synack_pkt:
        print("[-] NEM JÖTT SYN-ACK! Állj meg, ellenőrizd a hálózatot/P4-et.")
        return
    print("[+] SYN-ACK érkezett:")
    synack_pkt.show()

    # 2. 3-way handshake: ACK vissza
    SERVER_SEQ = synack_pkt[TCP].seq
    CLIENT_ACK = SERVER_SEQ + 1
    CLIENT_SEQ_NEXT = CLIENT_SEQ + 1

    print_step("2. ACK visszaküldése (3-way handshake 3. lépése)")
    ack = TCP(sport=SRC_PORT, dport=DST_PORT, flags="A", seq=CLIENT_SEQ_NEXT, ack=CLIENT_ACK)
    send(ip/ack, iface=IFACE, verbose=0)
    print(f"[+] ACK elküldve! seq={CLIENT_SEQ_NEXT} ack={CLIENT_ACK}")

    # 3. PSH+ACK adatküldés
    print_step("3. PSH+ACK (adat) küldése a switch felé")
    payload = b"Hello from client"
    pshack = TCP(sport=SRC_PORT, dport=DST_PORT, flags="PA", seq=CLIENT_SEQ_NEXT, ack=CLIENT_ACK)
    send(ip/pshack/payload, iface=IFACE, verbose=0)
    print(f"[+] PSH+ACK elküldve! seq={CLIENT_SEQ_NEXT}, ack={CLIENT_ACK}, adat: {payload}")

    # 4. Dummy válasz (PSH+ACK) figyelése
    print_step("4. Dummy válasz (PSH+ACK) figyelése a switch-től")

    def is_dummy(pkt):
        return (pkt.haslayer(TCP)
                and pkt[IP].src == DST_IP
                and pkt[TCP].sport == DST_PORT
                and "P" in pkt.sprintf("%TCP.flags%"))

    dummy_pkts = sniff(iface=IFACE, timeout=5, lfilter=is_dummy)
    if dummy_pkts:
        print(f"[+] Dummy válasz érkezett! ({len(dummy_pkts)} db)")
        for i, pkt in enumerate(dummy_pkts):
            print(f"\n== Dummy válasz #{i+1} ==")
            pkt.show()
            # Payload kiírás, ha van:
            if pkt.haslayer(Raw):
                data = pkt[Raw].load
                try:
                    print(f"[PAYLOAD ASCII]: {data.decode(errors='replace')}")
                except Exception:
                    print(f"[PAYLOAD]: {data}")
            else:
                print("[Nincs payload (Raw layer)]")
    else:
        print("[-] Nem érkezett dummy válasz a switch-től!")

    print("\n==== TESZT VÉGE ====")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[HIBA] {e}")
