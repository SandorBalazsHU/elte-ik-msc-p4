from scapy.all import *

# Cél IP és port
dst_ip = "10.0.0.2"
dst_port = 12345
src_port = 1234

print("[*] SYN küldése...")

# SYN csomag összeállítása
ip = IP(dst=dst_ip)
syn = TCP(sport=src_port, dport=dst_port, flags="S", seq=100)
pkt = ip/syn

# Válasz várása (SYN-ACK)
def synack_filter(pkt):
    return (
        pkt.haslayer(TCP)
        and pkt[IP].src == dst_ip
        and pkt[TCP].sport == dst_port
        and pkt[TCP].flags == 0x12  # SYN-ACK
    )

# Küldés és várakozás
send(pkt)
print("[*] Várakozás SYN-ACK válaszra...")

ans = sniff(timeout=3, lfilter=synack_filter)

if ans:
    print("[+] SYN-ACK válasz ÉRKEZETT! Handshake működik.")
    ans[0].show()
else:
    print("[-] Nem érkezett SYN-ACK válasz. Ellenőrizd a P4 switch-et.")
