#!/bin/bash

set -e

echo "⚙️ Fordítás: main.p4 → tcp_dummy.json"
p4c --target bmv2 --arch v1model -o tcp_dummy.json main.p4

echo "🚀 Mininet topológia indítása (1 switch, 2 host)..."
sudo mn -c > /dev/null 2>&1  # előző topológia törlése
sudo python3 tcp_topo.py &
MN_PID=$!

sleep 3

echo "📦 Szabályok betöltése a switch-re..."
echo "
table_add tcp_table send_synack 0x02 =>
table_add tcp_table send_dummy_response 0x18 =>
" > commands.txt

# wait for switch to come up
sleep 3

echo "💬 Teszt futtatása h1 hostról Scapy-val..."
xterm -e "sudo mnexec -a \$(pgrep -f h1-namespace) python3 scapy_tcp_handshake_test.py; read -p 'Press enter to close'" &

wait $MN_PID
