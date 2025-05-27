from scapy.all import *
import time
import threading

# === Színezés (ANSI escape codes) ===
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def c(color, text):
    return f"{color}{text}{RESET}"

# === Paraméterek ===
DST_IP = "10.0.0.2"
DST_PORT = 1010
SRC_IP = "10.0.0.1"
SRC_PORT = 1175
CLIENT_SEQ = 100
IFACE = "h1-eth0"

# --- Csomag típus felismerők ---
def is_syn(pkt):
    return pkt.haslayer(TCP) and pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10

def is_synack(pkt):
    return pkt.haslayer(TCP) and pkt[TCP].flags & 0x12 == 0x12

def is_ack(pkt):
    return pkt.haslayer(TCP) and pkt[TCP].flags & 0x10 and not pkt[TCP].flags & 0x08 and not pkt[TCP].flags & 0x02

def is_psh(pkt):
    return pkt.haslayer(TCP) and pkt[TCP].flags & 0x08

def role(pkt):
    if pkt[IP].src == SRC_IP:
        return "CLIENT"
    elif pkt[IP].src == DST_IP:
        return "SWITCH"
    return "UNKNOWN"

def pretty_flags(pkt):
    flags = pkt[TCP].flags
    flag_str = ""
    if flags & 0x02: flag_str += "SYN "
    if flags & 0x10: flag_str += "ACK "
    if flags & 0x08: flag_str += "PSH "
    if flags & 0x04: flag_str += "RST "
    if flags & 0x01: flag_str += "FIN "
    return flag_str.strip()

def pretty_payload(pkt):
    if pkt.haslayer(Raw):
        pl = pkt[Raw].load
        try:
            return pl.decode(errors="replace")
        except:
            return str(pl)
    return ""

def color_role(role):
    if role == "CLIENT":
        return c(BLUE, "[CLIENT]")
    elif role == "SWITCH":
        return c(GREEN, "[SWITCH]")
    return c(RED, "[?]")

def print_banner():
    print("\n" + "="*65)
    print(c(BOLD + CYAN, "    P4 TCP PIPELINE - MINDEN CSOMAGOS VIZUÁLIS TESZT & ELEMZÉS"))
    print("="*65 + "\n")

def print_step(msg):
    print("\n" + c(YELLOW, "─"*52))
    print(c(YELLOW, f"{msg:^52}"))
    print(c(YELLOW, "─"*52))

def main():
    print_banner()
    ip = IP(src=SRC_IP, dst=DST_IP)

    print_step("1. Indul a sniffer (background) és a teljes tesztfolyamat")
    # Async sniffer
    packets = []

    def pkt_callback(pkt):
        # Debug minden érkező csomagról
        print(c(YELLOW, f"[DEBUG] Sniffer kapott TCP csomagot: {pkt.summary()}"))
        packets.append(pkt)

    sniffer = AsyncSniffer(iface=IFACE, filter="tcp", prn=pkt_callback, store=False)
    sniffer.start()
    print(c(BLUE, "[*] Sniffer elindítva háttérben."))

    time.sleep(0.2)  # kis várakozás, hogy biztosan fusson a sniffer

    # 2. SYN küldése
    print_step("2. SYN küldése")
    syn = TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=CLIENT_SEQ)
    print(c(BLUE, f"Küldött SYN: {SRC_IP}:{SRC_PORT} -> {DST_IP}:{DST_PORT} SEQ={CLIENT_SEQ}"))
    send(ip/syn, iface=IFACE, verbose=0)

    time.sleep(0.5)  # várj fél másodpercet (pipeline-nak, hogy válaszoljon)

    # 3. ACK küldése
    print_step("3. ACK visszaküldése")
    CLIENT_SEQ_NEXT = CLIENT_SEQ + 1
    ack = TCP(sport=SRC_PORT, dport=DST_PORT, flags="A", seq=CLIENT_SEQ_NEXT, ack=CLIENT_SEQ_NEXT)
    print(c(BLUE, f"Küldött ACK: SEQ={CLIENT_SEQ_NEXT}, ACK={CLIENT_SEQ_NEXT}"))
    send(ip/ack, iface=IFACE, verbose=0)

    time.sleep(0.2)

    # 4. PSH+ACK küldése
    print_step("4. PSH+ACK (adat) küldése")
    payload = b"Hello from client"
    pshack = TCP(sport=SRC_PORT, dport=DST_PORT, flags="PA", seq=CLIENT_SEQ_NEXT, ack=CLIENT_SEQ_NEXT)
    print(c(BLUE, f"Küldött PSH+ACK: SEQ={CLIENT_SEQ_NEXT}, ACK={CLIENT_SEQ_NEXT}, payload={payload}"))
    send(ip/pshack/payload, iface=IFACE, verbose=0)

    print(c(BOLD, f"\nVárunk 2 másodpercet a csomagokra..."))
    time.sleep(2.0)  # várj a válaszokra

    print(c(BOLD, "[*] Sniffer leállítása, csomagok feldolgozása..."))
    sniffer.stop()

    print_step("5. KAPTUK A CSOMAGOKAT – ELEMZÉS\n")

    # Csomagok szűrése (csak TCP)
    pkts = [p for p in packets if p.haslayer(TCP)]

    for i, pkt in enumerate(pkts):
        r = role(pkt)
        col_role = color_role(r)
        flags = pretty_flags(pkt)
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        pl = pretty_payload(pkt)
        info = f"{col_role} {c(YELLOW, flags):<15} {c(CYAN, f'SEQ={seq} ACK={ack}')}"
        print(f"{i+1:02d}. {info}")
        if pl:
            print("    " + c(GREEN if r=="SWITCH" else BLUE, f"PAYLOAD: '{pl}'"))

    # Értékelés: handshake, payload, dummy válasz?
    print_step("6. ÖSSZEGZÉS")

    found = {"syn": False, "synack": False, "ack": False, "psh_client": False, "psh_switch": False}

    for pkt in pkts:
        if role(pkt) == "CLIENT" and is_syn(pkt):
            found["syn"] = True
        elif role(pkt) == "SWITCH" and is_synack(pkt):
            found["synack"] = True
        elif role(pkt) == "CLIENT" and is_ack(pkt):
            found["ack"] = True
        elif role(pkt) == "CLIENT" and is_psh(pkt):
            found["psh_client"] = True
        elif role(pkt) == "SWITCH" and is_psh(pkt):
            found["psh_switch"] = True

    # Összegzés kiírás
    print()
    print(c(BOLD + YELLOW, "== HANDSHAKE LÉPÉSEK ============="))
    print("  SYN        :", c(GREEN if found["syn"] else RED, str(found["syn"])))
    print("  SYN-ACK    :", c(GREEN if found["synack"] else RED, str(found["synack"])))
    print("  ACK        :", c(GREEN if found["ack"] else RED, str(found["ack"])))
    print(c(BOLD + YELLOW, "== PAYLOAD LÉPÉSEK ==============="))
    print("  PSH+ACK (client):", c(GREEN if found["psh_client"] else RED, str(found["psh_client"])))
    print("  PSH+ACK (switch):", c(GREEN if found["psh_switch"] else RED, str(found["psh_switch"])))

    if all(found.values()):
        print(c(BOLD + GREEN, "\n*** A P4 PIPELINE ÉS TCP HANDSHAKE TELJESEN OKÉ! ***\n"))
    else:
        print(c(BOLD + RED, "\n*** VALAMI LÉPÉS HIÁNYZIK! Ellenőrizd a csomagokat! ***\n"))

    print("="*65 + "\n")
    print(c(BOLD + CYAN, "Teszt vége. Ha további részleteket szeretnél kiírni, bővítsd a scriptet!"))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(c(RED, f"\n[HIBA] {e}"))
