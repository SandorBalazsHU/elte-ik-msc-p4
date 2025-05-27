from scapy.all import *

# --- Tesztkörnyezet paraméterek ---
dst_ip = "10.0.0.2"
dst_port = 1010
src_ip = "10.0.0.1"         # ha szükséges, külön beállítható
src_port = 1175
client_seq = 100            # kiindulási szekvenciaszám

def print_banner():
    print("="*40)
    print("      P4 SWITCH TCP HANDSHAKE TEST     ")
    print("="*40)

def main():
    print_banner()

    ip = IP(src=src_ip, dst=dst_ip)

    # --- 1. SYN küldése ---
    print("\n[*] 1. SYN küldése...")
    syn = TCP(sport=src_port, dport=dst_port, flags="S", seq=client_seq)
    synack_pkt = sr1(ip/syn, timeout=3)
    if not synack_pkt:
        print("[-] Nem érkezett SYN-ACK válasz. Teszt leáll.")
        return
    print("[+] SYN-ACK érkezett!")
    synack_pkt.show()

    # --- 2. 3-way handshake: ACK vissza ---
    server_seq = synack_pkt[TCP].seq
    client_ack = server_seq + 1
    client_seq_next = client_seq + 1
    print(f"\n[*] 2. ACK visszaküldése (3-way handshake 3. lépése)...")
    ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=client_seq_next, ack=client_ack)
    send(ip/ack)
    print(f"[+] ACK elküldve! seq={client_seq_next} ack={client_ack}")

    # --- 3. PSH+ACK adatküldés ---
    payload = b"Hello from client"
    pshack = TCP(sport=src_port, dport=dst_port, flags="PA", seq=client_seq_next, ack=client_ack)
    print(f"\n[*] 3. PSH+ACK (adat) küldése...")
    print(f"    SEQ={client_seq_next}  ACK={client_ack}")
    send(ip/pshack/payload)
    print("[+] PSH+ACK elküldve.")

    # --- 4. Dummy válasz figyelése ---
    def is_dummy(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt[IP].src == dst_ip
            and pkt[TCP].sport == dst_port
            and pkt[TCP].flags & 0x18 == 0x18  # PSH + ACK
        )

    print("\n[*] 4. Dummy válasz (PSH+ACK) figyelése a switch-től (5s timeout)...")
    dummy = sniff(timeout=5, lfilter=is_dummy)
    if dummy:
        print("[+] Dummy válasz érkezett a switch-től:")
        dummy[0].show()
        # Próbáljuk kiolvasni a payloadot is
        if dummy[0].haslayer(Raw):
            print(f"[PAYLOAD]: {dummy[0][Raw].load}")
        elif dummy[0].haslayer("payload_t"):
            print(f"[PAYLOAD (custom header)]: {dummy[0]['payload_t'].fields}")
    else:
        print("[-] Nem érkezett dummy válasz.")

    print("\n=== TESZT VÉGE ===")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[HIBA] Kivétel történt: {e}")
