""" Function to extrat packet from a .pcap and store them in a .bin"""

from scapy.all import rdpcap, TCP
import os

def extract_tls_payloads(pcap_file, output_dir="tools/tls_payloads"):
    packets = rdpcap(pcap_file)
    os.makedirs(output_dir, exist_ok=True)

    count = 0
    for pkt in packets:
        if TCP in pkt and pkt[TCP].dport == 443 and pkt[TCP].payload:
            raw_data = bytes(pkt[TCP].payload)
            out_file = os.path.join(output_dir, f"tls_payload_{count}.bin")
            with open(out_file, "wb") as f:
                f.write(raw_data)
            print(f"Saved: {out_file} ({len(raw_data)} bytes)")
            count += 1

    if count == 0:
        print("No TLS payloads found.")
    else:
        print(f"Extracted {count} TLS payloads.")

if __name__ == "__main__":
    extract_tls_payloads("tools/tls_capture.pcap")
