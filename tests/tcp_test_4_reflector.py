from scapy.all import *
import socket

# Cél IP és port
target_ip = "10.0.0.2"
target_port = 9090
source_port = RandShort()  # Random for testing

# 1. Küldjünk egy TCP csomagot (például egy SYN)
ip = IP(dst=target_ip)
tcp = TCP(sport=source_port, dport=target_port, flags="S", seq=100)
pkt = ip / tcp

print(f"📤 Csomag küldése {target_ip}:{target_port} -> {source_port} (SYN)")
send(pkt)

# 2. Várjunk és írjunk ki MINDENT, ami visszajön
def packet_callback(packet):
    print("📥 Bejövő csomag:")
    print(hexdump(packet))
    print("-" * 40)

print("🔍 Várakozás bármilyen bejövő csomagra...")
sniff(
    filter=f"tcp and port {source_port}",  # csak a visszatérő forgalmat figyeljük
    prn=packet_callback,
    timeout=5  # állítsd hosszabbra ha kell
)
