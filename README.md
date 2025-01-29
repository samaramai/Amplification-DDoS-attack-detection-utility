# Amplification DDoS Attack Detection Utility
This project is a simple Linux utility, which detects the following attacks:
- Amplification-based DDoS attacks
- Port scanning

The utility does the following steps:
1.	Listens for traffic on the network interface.
2.	Collects statistics about ICMP (code3 , type 3) and TCP (RST) packets in the outgoing server traffic. 
3.	Adds the detected attacker's IP address to the blacklist when the number of ICMP (code 3, type 3) or TCP (RST) packets exceeds the predefined threshold.
4.	Blocks traffic from the attacker's IP address for 5 minutes using the iptables firewall.
## Requirements (Debian GNU/Linux, Ubuntu)
apt install libpcap-dev build-essential
## How to run
For logging dropped packets using iptables:

iptables -N LOG_DROP

iptables -A LOG_DROP -j LOG --log-prefix "INPUT:DROP: " --log-level 6

iptables -A LOG_DROP -j DROP

gcc -march=native -O2 -lpcap -lpthread firewall.c -o firewall

./firewall

### The project is under development.
