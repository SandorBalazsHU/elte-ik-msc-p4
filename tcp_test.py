from scapy.all import *

dst_ip = "10.0.0.2"
dst_port = 9090
src_port = 9090
seq = 100

def send_syn():
    print("[*] 1. SYN küldése...")
    ip = IP(dst=dst_ip)
    syn = TCP(sport=src_port, dport=dst_port, flags="S", seq=seq)
    print(f"  Küldött SYN: {ip/syn}")
    send(ip/syn)
    return ip


def is_synack(pkt):
    return (
        pkt.haslayer(TCP)
        and pkt[IP].src == dst_ip
        and pkt[TCP].sport == dst_port
        and pkt[TCP].flags == 0x12  # SYN + ACK
    )

def is_dummy_response(pkt):
    return (
        pkt.haslayer(TCP)
        and pkt[IP].src == dst_ip
        and pkt[TCP].sport == dst_port
        and pkt[TCP].flags == 0x18  # PSH + ACK
    )

def main():
    # Küldd el a SYN-t
    ip = send_syn()

    print("[*] 2. SYN-ACK-re várakozás...")
    synack = sniff(timeout=5, lfilter=is_synack)

    if not synack:
        print("[-] Nem érkezett SYN-ACK válasz.")
        print("  Ellenőrizd a hálózati kapcsolatokat vagy a switch és host konfigurációját.")
        exit()

    print("[+] SYN-ACK érkezett!")
    synack_pkt = synack[0]
    print(f"  Kapott SYN-ACK: {synack_pkt.show()}")

    ack_seq = synack_pkt[TCP].ack
    ack_ack = synack_pkt[TCP].seq + 1

    # Küldjünk PSH+ACK-et, mint egy egyszerű üzenetküldés
    payload = "Hello from client"
    psh_ack = TCP(
        sport=src_port,
        dport=dst_port,
        flags="PA",
        seq=ack_seq,
        ack=ack_ack
    )

    print(f"[*] 3. PSH+ACK csomag küldése (adat: '{payload}')...")
    print(f"  Küldött PSH+ACK: {ip/psh_ack/payload}")
    send(ip/psh_ack/payload)

    # Válasz (dummy response) figyelése
    print("[*] 4. Dummy válaszra várakozás...")
    dummy = sniff(timeout=5, lfilter=is_dummy_response)

    if dummy:
        print("[+] Dummy válasz ÉRKEZETT!")
        print(f"  Kapott dummy válasz: {dummy[0].show()}")
    else:
        print("[-] Nem érkezett dummy válasz.")
        print("  Ellenőrizd a hálózati konfigurációt és a P4 switch működését.")
        exit()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Hiba történt: {e}")
        exit(1)
