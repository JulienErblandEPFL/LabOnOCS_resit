# MITM Attack Automation Toolkit – Julien Erbland Resit
This project was developed as part of the 2IC80 Lab on Offensive Computer Security. It implements a modular and scriptable tool for launching **ARP poisoning** and **DNS spoofing** attacks in a virtual network environment using Python and Scapy.
## Features 
- **ARP Spoofing**: Places the attacker in a man-in-the-middle (MITM) position between selected victims and the gateway. Supports multiple targets. Includes Normal MITM and Anonymous SMITM modes. Customizable spoofing interval. Automatic ARP table restoration on exit. 
- **DNS Spoofing**: Intercepts DNS queries and responds with forged answers based on a user-defined domain-to-IP mapping. No need to win race conditions thanks to MITM position. Built with NetfilterQueue for real-time packet manipulation. Includes live logging and clean teardown logic.
## Requirements 
- Python 3.6+ 
- Linux system with root privileges 
- The following Python dependencies: 
- `scapy==2.2.0` 
- `netfilterqueue` 
Install dependencies with: ```pip install -r requirements.txt ``` 

## How to Use 
1. Run `main.py` as root: ```sudo python3 main.py ``` 
2. Select the network interface and scan the network. 
3. Choose one or multiple targets and gateway. 
4. Start ARP spoofing or ARP + DNS spoofing. 
5. Provide domains to spoof and the fake IPs. 
6. Press `Ctrl+C` to stop. ARP tables will be automatically restored.