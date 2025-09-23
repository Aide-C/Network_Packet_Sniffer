from scapy.all import *
import logging
import os
import smtplib
from collections import defaultdict
from datetime import datetime
from email.message import EmailMessage
from dotenv import load_dotenv

logging.basicConfig(
    filename="alerts.log",
    level=logging.WARRING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)
load_dotenv()

senderEmail = os.getenv("SENDEREMAIL")
password = os.getenv("PASSWORD") 
recieverEmail = os.getenv("EMAIL")

def email_alert(message):
    msg = EmailMessage()
    msg["From"] = senderEmail
    msg["To"] = recieverEmail
    msg["Subject"] = "****Network Security Alert****"
    msg.set_content(message)

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(senderEmail, password)
            server.send_message(msg)
            print("------Email was sent successfully------")
    except Exception as e:
        print(f"Error sending email: {e}")

trackSyn = defaultdict(int)
trackArp = defaultdict(str)
trackDns = defaultdict(str)

def packet_info(packet):
    if packet.haslayer(IP):
        ip = None

        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:
            ip = packet[IP].src
            trackSyn[ip] += 1

            if trackSyn[ip] > 50:
                now = datetime.now()
                alertOne = f"Type: SYN flood attack\nSource IP address: {ip}\nTime: {now}\nInfo: More than 50 SYN packets from this IP address"
                print("****SECURITY ALERT: SYN flood attack****")
                logger.warning(f"{ip} : TCP - SYN flood attack: Abnormal burst of SYN packets from this IP address")
                email_alert(alertOne)

    if packet.haslayer(ARP) and packet[ARP].op == 2:
        srcIP = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if srcIP in trackArp:
            if trackArp[srcIP]!= mac:
                now = datetime.now()
                alertTwo = f"Type: ARP spoofing\nSource IP address: {srcIP}\nTime: {now}\nInfo: This IP address is not mapped to MAC address {mac}"
                print("****SECURTY ALERT: ARP Spoofing****")
                logger.warning(f"{srcIP} : ARP - ARP Spoofing - Duplicate IP address: This IP address is not mapped to MAC address '{mac}'.")
                email_alert(alertTwo)
        elif mac in trackArp:
            for key, value in trackArp.items():
                if mac == value and srcIP != key:
                    now = datetime.now()
                    alertThree = f"Type: ARP spoofing\nSource IP address: {srcIP}\nTime: {now}\nInfo: MAC address {mac} is not mapped to this IP address"
                    print("****SECURTY ALERT: ARP Spoofing****")
                    logger.warning(f"{srcIP} : ARP - ARP Spoofing - Duplicate MAC address: MAC address '{mac}' is not mapped to this IP address.")
                    email_alert(alertThree)
        else:
            trackArp[srcIP] = mac

    if packet.haslayer(DNS) and packet[DNS].qr == 1:
        dnsqr = packet[DNS].qd
        dnsrr = packet[DNS].an

        if dnsqr.qtype == 1:
            domain = dnsqr.qname
            webIP = dnsrr.rdata

            if domain in trackDns:
                if trackDns[domain] != webIP:
                    now = datetime.now()
                    alertFour = f"Type: DNS spoofing\nSource IP address: {webIP}\nTime: {now}\nInfo: {domain} is not mapped to IP address {webIP}"
                    print("****SECURITY ALERT: DNS Spoofing****")
                    logger.warning(f"{webIP} : DNS - DNS Spoofing: Domain '{domain}' is not mapped to this IP address.")
                    email_alert(alertFour)
            else:
                 trackDns[domain] = webIP



sniff(prn=packet_info)