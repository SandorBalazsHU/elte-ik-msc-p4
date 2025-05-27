#!/bin/bash

set -e

echo "⚙️ Fordítás: main.p4 → tcp_dummy.json"
p4c --target bmv2 --arch v1model -o tcp_dummy main.p4

echo "🚀 Mininet topológia indítása (1 switch, 2 host)..."

# -- ITT: iptables szabályok (switch gépen, azaz a host gépen, nem Minineten!)
echo "🛡️ IPTABLES szabályok hozzáadása a switch (host) oldalán..."
sudo iptables -A INPUT -i s1-eth1 -p tcp --dport 1010 -j DROP
sudo iptables -A INPUT -i s1-eth1 -p tcp --sport 1010 -j DROP

# Mininet indul
sudo mn -c > /dev/null 2>&1  # előző topológia törlése

echo "📦 Topológia és szabályok betöltése a tcp_topo.py segítségével..."
sudo python3 tcp_topo.py

rm -rf tcp_dummy

echo "🧹 Takarítás kész."
