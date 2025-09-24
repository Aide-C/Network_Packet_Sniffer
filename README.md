# Network_Packet_Sniffer
A custom-built packet sniffer to monitor the user's network traffic and analyze for cybersecurity threats. The primary objective of this project is to understand how attacks are conducted at the network layer and detect them. This was a standalone project on LinkedIn Learning.

## Description
As stated in the project summary above, this is a custom-built Python and Scapy packet sniffer that helps users identify and respond to incidents more quickly. It analyzes packets in the network in real-time and detects patterns associated with SYN flood attacks, ARP spoofing attacks, and DNS spoofing attacks. If any of the attacks are detected, it will print an alert to the terminal and log the attack's information into a "alerts.log" file. It also uses the smtplib module to send the user an email alerting them of the attack with relevant information. The sender's Gmail account, the sender's passkey, and the receiver's email are stored in a .env file to protect them from unauthorized users.  

## Getting Started
### Prerequisites
- Linux environment - preferably Kali Linux virtual machine (VirtualBox or VMware)
- Basic Linux skills (navigation and installing/managing packages)
- Basic network knowledge (IP addresses, MAC addresses, ports/protocols, data transmission)
- Python 
- Scapy
- Wireshark
- hping3
- arpspoof
- dnsspoof
- logging
- smtplib

### Installing
- Download file on GitHub
- Clone repository
- Fork the repository

### Executing Program
Open the terminal and in the file's directory, run the command to allow execute permission:
```
chmod +x network_packet_sniffer.py
```
Create a .env file to store the sender's Gmail, passkey, and the receiver's email. 
To execute the program, run the command:
```
sudo python3 network_packet_sniffer.py
```

## Author
Aide Cuevas (LinkedIn in profile)

## Version History
*  0.2
    * Add the ability to log security alerts as warnings to a log file called 'alerts.log'
    * Add the ability to send email alerts to the user with smptlib
    * Fix SYN detection by focusing on the quantity of SYN packets instead of timing

* 0.1
    * Added SYN flood attack detection, but had errors trying to time the detection every 5 seconds
    * Added ARP spoofing detection
    * Added DNS spoofing detection

## License
This project is licensed under the MIT license - see LICENSE.md file for details
