from scapy.all import *

# IP- és MAC-címek
h1_ip = "10.0.0.1"
sw_ip = "10.0.0.2"
h1_mac = "00:00:00:00:01:01"
sw_mac = "00:00:00:00:01:02"

iface = "h1-eth0"  # Vagy amit a Mininet h1-hez rendelt

# TCP állapot
client_seq = 1000

# 1. SYN küldése
syn = Ether(src=h1_mac, dst=sw_mac) / \
      IP(src=h1_ip, dst=sw_ip) / \
      TCP(sport=1234, dport=9090, flags="S", seq=client_seq)

print(">> Sending SYN")
synack = srp1(syn, iface=iface, timeout=2)

if synack and TCP in synack and synack[TCP].flags == 0x12:
    print("<< Got SYN-ACK")
    server_seq = synack[TCP].seq
    ack = Ether(src=h1_mac, dst=sw_mac) / \
          IP(src=h1_ip, dst=sw_ip) / \
          TCP(sport=1234, dport=9090, flags="A", seq=client_seq + 1, ack=server_seq + 1)
    sendp(ack, iface=iface)

    # 2. PSH (üres payload, csak a kapcsolat tesztelésére)
    psh = Ether(src=h1_mac, dst=sw_mac) / \
          IP(src=h1_ip, dst=sw_ip) / \
          TCP(sport=1234, dport=9090, flags="PA", seq=client_seq + 1, ack=server_seq + 1) / \
          Raw(load="Hi from host!")
    print(">> Sending PSH")
    response = srp1(psh, iface=iface, timeout=2)
    
    if response:
        print("<< Got response from switch:")
        response.show2()
    else:
        print("!! No response to PSH")
else:
    print("!! No SYN-ACK received")
