# MITM Attack Automation Toolkit – Group 29

This project is part of the 2IC80 Lab on Offensive Computer Security. It provides a modular tool that allows a user to perform ARP spoofing, DNS spoofing, and (partial) SSL stripping attacks in a virtual environment using Scapy.

> This tool is for educational and ethical hacking purposes only.

---

## Features

- **ARP Spoofing**: Intercepts traffic between a victim and a gateway.
- **DNS Spoofing** (optional): Redirects DNS queries to attacker-controlled IPs.
- **SSL Stripping** (prototype): Intercepts HTTP traffic and rewrites content to prevent HTTPS upgrades.

---

## Requirements

- Python 3.6+
- Linux OS with root privileges
- **Dependencies**:
  - `scapy==2.2.0`

## System Configuration

Before running the tool, you must configure your system for packet forwarding and proper network behavior. These settings are required for ARP spoofing, DNS spoofing, and SSL stripping to work correctly.

---

### Enable IP Forwarding

IP forwarding allows your machine to forward packets between interfaces, which is essential for any man-in-the-middle (MITM) attack.

#### Temporary (until reboot):
    ```bash
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

### Permanent Activation of IP Forwarding

To ensure IP forwarding remains enabled after a reboot, you must modify the system configuration:

1. Open the system configuration file:
   ```bash
   sudo nano /etc/sysctl.conf

2. Find the following line and uncomment it, or add it manually:
    ```bash
    net.ipv4.ip_forward=1

3. Save and exit

### Disable ICMP "Port Unreachable" Messages (Optional)

By default, your system may respond with ICMP "port unreachable" messages when it receives traffic on closed ports, which could interfere with packet interception during spoofing attacks.

To temporarily disable these responses, run:

    ```bash
    sudo iptables -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP
