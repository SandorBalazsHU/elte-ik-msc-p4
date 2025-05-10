from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from p4utils.mininetlib.node import P4Switch
import os

class SingleSwitchTopo(Topo):
    def build(self):
        # H1 host létrehozása fix IP-vel és MAC-cel
        h1 = self.addHost('h1',
                          mac='00:00:00:00:00:01',
                          ip='10.0.0.1/24')

        # P4 switch
        s1 = self.addSwitch('s1',
                            cls=P4Switch,
                            sw_path='simple_switch',
                            json_path='tcp_dummy/main.json',
                            thrift_port=9090,
                            pcap_dump=True,
                            pcap_dir='log',
                            device_id=0)

        # H1 kapcsolása s1-hez
        self.addLink(h1, s1)

def load_p4rules():
    print("📦 Szabályok betöltése...")

    # TCP táblaszabályok (flag szerint)
    os.system("echo 'table_add tcp_table send_synack 0x02 => ' | simple_switch_CLI --thrift-port 9090")
    os.system("echo 'table_add tcp_table send_dummy_response 0x18 => ' | simple_switch_CLI --thrift-port 9090")

    # MAC-alapú forwarding - port 1 (h1 csatlakozása)
    os.system("echo 'table_add dmac forward 00:00:00:00:00:01 => 1' | simple_switch_CLI --thrift-port 9090")
    os.system("echo 'table_add dmac forward 00:00:00:00:02:00 => 1' | simple_switch_CLI --thrift-port 9090")

if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=False, link=TCLink)
    net.start()

    # 🔧 Host konfigurálás
    h1 = net.get('h1')
    h1.cmd('ip addr flush dev h1-eth0')
    h1.cmd('ip addr add 10.0.0.1/24 dev h1-eth0')
    h1.cmd('ip link set dev h1-eth0 address 00:00:00:00:00:01')
    h1.cmd('ip link set dev h1-eth0 up')

    # 🌐 ARP bejegyzés a "válaszoló" switch címéhez
    h1.cmd('arp -s 10.0.0.2 00:00:00:00:02:00')

    # 🛠️ Switch interfész (port 1) IP/MAC beállítása — fontos!
    s1 = net.get('s1')
    s1.cmd('ip addr add 10.0.0.2/24 dev s1-eth1')
    s1.cmd('ip link set dev s1-eth1 address 00:00:00:00:02:00')
    s1.cmd('ip link set dev s1-eth1 up')

    # 🔁 Szabályok betöltése
    load_p4rules()

    print("\n✅ Hálózat kész. CLI következik.")
    print("🔍 Teszt: h1 python3 scapy_tcp_handshake_test.py")
    print("Kilépés: exit\n")
    CLI(net)

    net.stop()
