from scapy.all import *

# IP- és MAC-címek
h1_ip = "10.0.0.1"
sw_ip = "10.0.0.2"
h1_mac = "00:00:00:00:01:01"
sw_mac = "00:00:00:00:01:02"

iface = "h1-eth0"  # Vagy amit a Mininet h1-höz rendelt

# TCP állapot
client_seq = 1000

# 1. SYN küldése
syn = Ether(src=h1_mac, dst=sw_mac) / \
      IP(src=h1_ip, dst=sw_ip) / \
      TCP(sport=1234, dport=9090, flags="S", seq=client_seq)

print(">> Sending SYN")

sendp(syn, iface=iface)

# 2. Várakozás válaszokra
print("<< Listening for replies (5s)...")

def handle_pkt(pkt):
    print("<< Received packet:")
    pkt.show2()

sniff(iface=iface, timeout=5, prn=handle_pkt, filter="tcp")
