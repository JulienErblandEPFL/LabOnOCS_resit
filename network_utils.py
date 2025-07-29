from scapy.all import ARP, Ether, srp, get_if_hwaddr, get_if_addr, conf
import socket

def scan_network(ip_range, iface=None):
    # Sends a broadcast ARP request to the given subnet (ip_range)
    # Returns a list of active hosts as (IP, MAC) pairs

    arp_request = ARP(pdst=ip_range)  # Create an ARP request packet
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Create a broadcast Ethernet frame
    packet = broadcast / arp_request  # Combine them

    # Send the packet and receive responses
    answered, _ = srp(packet, timeout=2, iface=iface, verbose=False)

    hosts = []
    for _, response in answered:
        ip = response.psrc  # Source IP from response
        mac = response.hwsrc  # Source MAC from response
        #print("[+] Found: {} at {}".format(ip, mac))  # Display each found device
        hosts.append((ip, mac))  # Add to result list

    return hosts  # Return list of detected (IP, MAC)

def get_attacker_ip(iface=None):
    # Returns the attacker's IP address on the given interface
    iface = iface or conf.iface  # Use specified iface or Scapy default
    return get_if_addr(iface)

def get_attacker_mac(iface=None):
    # Returns the attacker's MAC address on the given interface
    iface = iface or conf.iface
    return get_if_hwaddr(iface)
