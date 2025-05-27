from scapy.all import *
import time

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
    results = []

    # 1. SYN küldése
    print_step("1. SYN küldése")
    syn = TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=CLIENT_SEQ)
    print(c(BLUE, f"Küldött SYN: {SRC_IP}:{SRC_PORT} -> {DST_IP}:{DST_PORT} SEQ={CLIENT_SEQ}"))
    sr1(ip/syn, iface=IFACE, timeout=2, verbose=0)

    # Sniffelés: minden TCP csomag rögzítése (kényelmesen hosszú timeout)
    print_step("2. TELJES TCP FORGALOM RÖGZÍTÉSE (10 mp)...")
    print(c(BOLD, "Küldd el az ACK-ot és a PSH+ACK-et, közben minden TCP csomagot sniffelünk."))
    print(c(BOLD, "Várj 1 másodpercet a forgalom " + c(RED, "leüléséig") + "..."))
    time.sleep(1)

    # Küldjük az ACK-ot
    CLIENT_SEQ_NEXT = CLIENT_SEQ + 1
    ack = TCP(sport=SRC_PORT, dport=DST_PORT, flags="A", seq=CLIENT_SEQ_NEXT, ack=CLIENT_SEQ_NEXT)
    send(ip/ack, iface=IFACE, verbose=0)
    print(c(BLUE, f"Küldött ACK: SEQ={CLIENT_SEQ_NEXT}, ACK={CLIENT_SEQ_NEXT}"))

    # Küldjük a PSH+ACK-et
    payload = b"Hello from client"
    pshack = TCP(sport=SRC_PORT, dport=DST_PORT, flags="PA", seq=CLIENT_SEQ_NEXT, ack=CLIENT_SEQ_NEXT)
    send(ip/pshack/payload, iface=IFACE, verbose=0)
    print(c(BLUE, f"Küldött PSH+ACK: SEQ={CLIENT_SEQ_NEXT}, ACK={CLIENT_SEQ_NEXT}, payload={payload}"))

    print(c(BOLD, "\nSniffelés 10 másodpercig indul... minden TCP csomag ki lesz írva!\n"))
    pkts = sniff(iface=IFACE, timeout=10, filter="tcp")

    print_step("3. KAPTUK A CSOMAGOKAT – ELEMZÉS\n")

    for i, pkt in enumerate(pkts):
        if not pkt.haslayer(TCP): continue
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
    print_step("4. ÖSSZEGZÉS")

    # Kiértékeljük az eseményeket
    # - SYN (client)
    # - SYN-ACK (switch)
    # - ACK (client)
    # - PSH+ACK (client, payload)
    # - PSH+ACK (switch, dummy payload)
    found = {"syn": False, "synack": False, "ack": False, "psh_client": False, "psh_switch": False}

    for pkt in pkts:
        if not pkt.haslayer(TCP): continue
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

    if found["syn"] and found["synack"] and found["ack"] and found["psh_client"] and found["psh_switch"]:
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
