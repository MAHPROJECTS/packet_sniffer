
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from datetime import datetime

def show_packet(packet):
    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    source = packet[IP].src
    destination = packet[IP].dst
    source = packet[IP].src
    destination = packet[IP].dst

    if DNS in packet:
        protocol = "DNS"

        if DNSQR in packet and packet[DNS].qr == 0:
            name = packet[DNSQR].qname

            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")

            print(
                f"{timestamp} | {source} -> {destination} | "
                f"{protocol} query: {name}"
            )
            return

    elif TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other IP"

    print(f"{timestamp} | {source} -> {destination} | {protocol}")

print("Network Packet Sniffer")
print("Capturing 30 packets...")

sniff(prn=show_packet, count=100, store=False)

print("Capture finished!")
