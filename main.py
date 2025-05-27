from parser.tls_record import TLSRecord 
from common.exceptions import *

sample_tls_packet = bytes.fromhex(
        '16 03 01 00 dc'  # Record header: Handshake, TLS 1.0, length = 220 bytes
        '01 00 00 d8'      # Handshake: type=ClientHello, length=216
        '03 03'            # Version: TLS 1.2
        '5d b8 d7 0e b5 c2 c1 2a f9 4b 76 b3 a1 0e 6f b0'
        'f3 33 b1 6e 2f 3f 16 50 77 12 f0 1e f3 4f c3 0b'  # Random (32 bytes)
        '00'              # Session ID Length: 0
        '00 20'           # Cipher Suites length: 32 bytes (16 suites)
        'c0 2f c0 2b c0 0a c0 09 c0 13 c0 14 00 9c 00 9d'
        '00 2f 00 35 00 0a 01 00'  # Cipher suites (truncated)
        '01 00'           # Compression methods length + null
        '00 74'           # Extensions length: 116 bytes
        '00 00 00 0e 00 0c 00 00 09 6c 6f 63 61 6c 68 6f 73 74'
        # (extensions truncated for brevity)
        '00 00'
    )

sample_tls_packet_2 = bytes.fromhex(
        '16 03'
    )

sample = bytes.fromhex(
    "16 03 05 00 2f "  # TLS record header: Handshake, TLS 1.0, 47 bytes
    "01 00 00 2b"     # Handshake message: ClientHello (0x01), length 43 bytes
    "03 03"           # ClientHello version: TLS 1.2
    "53 4c 4e 00 00 00 00 00 00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"  # Random
    "00"             # Session ID length: 0
    "00 02"          # Cipher Suites length: 2 bytes
    "00 3c"          # Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA
    "01"             # Compression Methods Length: 1
    "00"             # Compression Method: null
    "00 00"
)

sample_alert = bytes.fromhex(
    "10 03 03 00 " # TLS record header: Alert TLS 1.2 , 2bytes
    "02" # Alert lvl Fatal
    "28" # Alert Description= Handshake Failure (40/0x28)
)

sample_css = bytes.fromhex(
    "14 03 03 00 01" # TLS record header: Change Cipher Spec TLS 1.2 , 2bytes
    "01"
)


client_hello_bytes = bytes.fromhex(
    "16 03 01 00 31"
    "01 00 00 49" 
    "03 03"
    "53 43 5b 90 4b 90 95 6b 3f f2 1f 63 55 5d b0 3a"
    "13 66 8c 60 e8 ab 82 56 d0 36 4c 9b 41 0e 231c"
    "00"
    "00 04"
    "00 2f 00 35"
    "01"
    "00"
    "00 00"
)
#print(len(sample))
# record = TLSRecord(sample)
# try:
#     record.parse()
# except IncompletePayloadError as e:\\\
#     print("Record error: ", e)
# record_2 = TLSRecord(sample)

# try:
#     record_2.parse()
# except UnknownTLSVersionError as e:
#     print("Record error: ", e)
# print(record_2)


# PLACEHOLDER_VALUE = b'\xFF'
# print(PLACEHOLDER_VALUE.hex() * 2)

#print(len(sample_tls_packet))
#print(record_2)

# tls_alert_packet = TLSRecord(sample_alert)
# try:
#     tls_alert_packet.parse()
# except IncompleteHeaderError as e:
#    print("Error: ", e)

# print(tls_alert_packet)
#print(tls_alert_packet.parsed_payload)

# tls_css_packet = TLSRecord(sample_css)
# tls_css_packet.parse()
# print(tls_css_packet)


# tls_handshake_packett = TLSRecord(sample_tls_packet)
# tls_handshake_packett.parse()
# try:
#     tls_handshake_packett.parse()
# except Exception as e:
#     print("parsing error: ", e)
#print(tls_handshake_packett)
#print(tls_handshake_packett.parsed_payload.raw_handshake.hex())


# tls_test = TLSRecord(client_hello_bytes)
# tls_test.parse()
# print(tls_test)


client_hello_packet = bytes.fromhex(
    "16 03 03 00 30"                  # TLS Record Header: ContentType=22 (Handshake), Version=1.2, Length=46
    "01 00 00 2c"                    # Handshake Header: Type=1 (ClientHello), Length=42
    "03 03"                          # ClientHello Version: TLS 1.2
    "00 01 02 03 04 05 06 07"        # Random (first 8 bytes shown)
    "08 09 0A 0B 0C 0D 0E 0F"
    "10 11 12 13 14 15 16 17"
    "18 19 1A 1B 1C 1D 1E 1F"
    "01"                             # Session ID Length
    "AA"                             # Session ID
    "00 04"                          # Cipher Suites Length: 4 bytes = 2 suites
    "00 2F 00 35"                    # Cipher Suites: TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
    "01"                             # Compression Methods Length
    "00"                             # Compression Method: null
)

# tls_client_hello_test = TLSRecord(client_hello_packet)
# try:
#     tls_client_hello_test.parse()
# except Exception as e:
#     print("Erroare de parsare", e)
#print(tls_client_hello_test)

# print(tls_client_hello_test.parsed_payload.handshake_payload.version)
# print(tls_client_hello_test.parsed_payload.handshake_payload.random)
# print(tls_client_hello_test.parsed_payload.handshake_payload.session_id_length)
# print(tls_client_hello_test.parsed_payload.handshake_payload.session_id)
# print(tls_client_hello_test.parsed_payload.handshake_payload.cipher_suites_length)
# print(tls_client_hello_test.parsed_payload.handshake_payload.cipher_suites)
# print(tls_client_hello_test.parsed_payload.handshake_payload.compression_meth_length)
# print(tls_client_hello_test.parsed_payload.handshake_payload.compression_meth)
# print(tls_client_hello_test.parsed_payload.handshake_payload.extenssions)
# print(tls_client_hello_test)


server_hello_packet = bytes.fromhex(
    "16"        # Content Type: Handshake
    "03 03"     # TLS Version: 1.2
    "00 41"     # Length: 43 bytes  am nevoie de 65 = 

    "02"        # Handshake Type: ServerHello
    "00 00 3d"  # Length: 38 bytes  61
    "03 03"     # ServerHello Version: TLS 1.2

    "11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00"
    "10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0 00"  # Random (32 bytes)

    "01 00"        # Session ID Length: 0
    "00 2f"     # Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA
    "00"        # Compression Method: null

    "00 14"
    "00 00"        # Extension Type: 0x0000 (SNI)
    "00 10"        # Extension Length: 16 bytes

    "00 0f"        # Server Name List Length: 15 bytes
    "00"           # Server Name Type: host_name
    "00 0c"        # Server Name Length: 12 bytes
    "65 78 61 6d 70 6c 65 2e 63 6f 6d"  # Server Name: "example.com"
)

server_hello_test = TLSRecord(server_hello_packet)
try:
    server_hello_test.parse()
except Exception as e:
    print("Erroare de parsare", e)
print(server_hello_test)
#print(server_hello_test.payload.handshake_payload.extensions.count())
