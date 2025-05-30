import os
from parser.tls_record import TLSRecord 
from common.exceptions import *
from tools.test_data import *

def main():
    #test_tls_payload_parsing()

    test_packets = []
    test_packets.append(sample_alert)
    test_packets.append(sample_css)
    test_packets.append(sample_client_hello)
    test_packets.append(sample_server_hello)
    
    for pkt in client_hellos:
        packet = bytes.fromhex(pkt)
        test_packets.append(packet)
    for pkt in server_hellos:
        packet = bytes.fromhex(pkt)
        test_packets.append(packet)
    for pkt in truncated:
        packet = bytes.fromhex(pkt)
        test_packets.append(packet)
    for pkt in wireshark_packets:
        packet = bytes.fromhex(pkt)
        test_packets.append(packet)

    log_file = "tools/tls_parse_sample_data_results.txt"
    with open(log_file, "w") as log:
        for index, value in enumerate(test_packets):
            packet = TLSRecord(value)
            log.write(f"----------Parsing packet no: {index} -----------\n")
            try:
                packet.parse()
                log.write(f"{packet} \n")
            except Exception as e:
                log.write(f"Failed to parse {index}: {e.__class__.__name__} - {e}")


# testing packets extracted from tcpdump capture
def test_tls_payload_parsing(payloads_dir="tools/tls_payloads", log_file="tools/tls_parse_results.txt"):
    with open(log_file, "w") as log:
        for filename in os.listdir(payloads_dir):
            file_path = os.path.join(payloads_dir, filename)
            with open(file_path, "rb") as f:
                data = f.read()
            log.write(f"\n --- Parsing: {filename} ---")
            #print(f"\n --- Parsing: {filename} ---")
            
            try:
                record = TLSRecord(data)
                record.parse()
                log.write(str(record) + "\n")
                #print(record)
            except Exception as e:
                log.write(f"Failed to parse {filename}: {e.__class__.__name__} - {e}")
                #print(f"Failed to parse {filename}: {e.__class__.__name__} - {e}")

if __name__ == "__main__":
    main()
