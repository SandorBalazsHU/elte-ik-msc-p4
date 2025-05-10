from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from p4utils.mininetlib.node import P4Switch
import os

class SingleSwitchTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        s1 = self.addSwitch('s1',
                            cls=P4Switch,
                            sw_path='simple_switch',
                            json_path='tcp_dummy/main.json',
                            thrift_port=9090,
                            pcap_dump=False,
                            device_id=0)
        self.addLink(h1, s1)

def load_p4rules():
    print("📦 Szabályok betöltése...")

    # TCP válaszok (flag alapján)
    os.system("echo 'table_add tcp_table send_synack 0x02 =>' | simple_switch_CLI --thrift-port 9090")
    os.system("echo 'table_add tcp_table send_dummy_response 0x18 =>' | simple_switch_CLI --thrift-port 9090")

    # MAC-alapú forwarding (dmac tábla)
    os.system("echo 'table_add dmac forward 00:00:00:00:00:01 => 1' | simple_switch_CLI --thrift-port 9090")


if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=True, link=TCLink)
    net.start()

    # 💡 Statikus ARP beállítás h1-en: 10.0.0.2 IP → dummy MAC (amit a switch impersonál)
    h1 = net.get('h1')
    net.get('h1').cmd('arp -s 10.0.0.2 00:00:00:00:02:00')

    load_p4rules()
    
    print("✅ Topológia elindult. CLI következik.")
    print("Teszteléshez futtasd:  h1 python3 scapy_tcp_handshake_test.py")
    print("Kilépéshez: exit")
    CLI(net)
    net.stop()
