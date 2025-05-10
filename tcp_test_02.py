from scapy.all import *

ip = IP(dst="10.0.0.2", src="10.0.0.1")
syn = TCP(sport=1175, dport=1010, flags='S', seq=100)
pkt = ip/syn
send(pkt)

# várunk választ
ans = sniff(count=1, timeout=2)
ans[0].show()
