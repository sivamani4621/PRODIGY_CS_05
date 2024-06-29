from scapy.all import sniff, IP, TCP, UDP, Ether

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Check if the packet is a TCP packet
        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        # Check if the packet is a UDP packet
        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            protocol = "Other"
            sport = dport = None

        print(f"Protocol: {protocol} | Source IP: {ip_src} | Source Port: {sport} | Destination IP: {ip_dst} | Destination Port: {dport}")
    else:
        print("Non-IP Packet")

# Sniff packets and use the packet_callback function for each packet
sniff(prn=packet_callback, store=0)
