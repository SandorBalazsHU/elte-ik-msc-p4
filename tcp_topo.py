#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, Host, OVSSwitch
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

import os

class P4Topo(Topo):
    def build(self):
        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')

        # Switch (bmv2)
        s1 = self.addSwitch('s1')

        # Links
        self.addLink(h1, s1)
        self.addLink(h2, s1)

def start_p4_switch():
    # Indítsd a bmv2 switch-et külön terminálból is, ha kell
    cmd = (
        "simple_switch "
        "--log-console "
        "-i 0@veth0 -i 1@veth1 "
        "tcp_dummy.json"
    )
    print("Futtasd a következő parancsot külön terminálból:")
    print(cmd)

def main():
    topo = P4Topo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=True, link=TCLink)
    net.start()

    h1, h2 = net.get('h1', 'h2')
    h1.cmd("ip route add default via 10.0.0.254")
    h2.cmd("ip route add default via 10.0.0.254")

    print(">>> Hálózat elindult")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()
