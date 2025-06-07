from scapy.all import rdpcap, TCP
import struct

def extract_tls_packet_from_file(pcap_path):
    packets = rdpcap(pcap_path)
    payloads = []
    for pkt in packets:
        if TCP in pkt and pkt[TCP].dport == 443 and pkt[TCP].payload:
            payloads.append(bytes(pkt[TCP].payload))
    return payloads