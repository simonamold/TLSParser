from parser.tls_record import TLSRecord 
from common.exceptions import *

import os

from parser.tls_record import TLSRecord


def test_tls_payload_parsing(payloads_dir="tools/tls_payloads"):
    for filename in os.listdir(payloads_dir):
        file_path = os.path.join(payloads_dir, filename)
        with open(file_path, "rb") as f:
            data = f.read()

        print(f"\n --- Parsing: {filename} ---")
        #print(data.hex())
        try:
            record = TLSRecord(data)
            record.parse()
            print(record)
        except Exception as e:
            print(f"Failed to parse {filename}: {e.__class__.__name__} - {e}")


if __name__ == "__main__":
    test_tls_payload_parsing()


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

# server_hello_test = TLSRecord(server_hello_packet)
# try:
#     server_hello_test.parse()
# except Exception as e:
#     print("Erroare de parsare", e)
# print(server_hello_test)
#print(server_hello_test.payload.handshake_payload.extensions.count())

sample_client_hello = bytes.fromhex(
    "16 03 01 00 f8" \
    "01 00 00 f4 03 " \
    "03 00 01 02 03 04 05 06 07 08 " \
    "09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 " \
    "17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb " \
    "ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 " \
    "01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e " \
    "6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 " \
    "01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 " \
    "09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 " \
    "26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 " \
    "d0 d2 cd 16 62 54"
)

sample_server_hello = bytes.fromhex(
    "16 03 03 00 7a 02 00 00 76 03 03 70 71 72 73 74 75 " \
    "76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 " \
    "8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 " \
    "f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 9f d7 ad " \
    "6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15"
    
)

# tls_sample_client_record = TLSRecord(sample_client_hello)
# try:
#     tls_sample_client_record.parse()
# except Exception as e:
#     print("Erroare de parsare", e)
# print(tls_sample_client_record)

# tls_sample_server_record = TLSRecord(sample_server_hello)
# try:
#     tls_sample_server_record.parse()
# except Exception as e:
#     print("Erroare de parsare", e)
# print(tls_sample_server_record)

real_client_hello_wireshark = bytes.fromhex("16030107180100071403036d697ac841b4ee8f8" \
"884843a14fc5413f80fd7f5490be5cb28c2e184a1c5c7d020bc7c2b3fc3d57b795512f30d12f24db52b0" \
"9fdf856d24f15b08db8af84eddced0020caca130113021303c02bc02fc02cc030cca9cca8c013c014009c" \
"009d002f0035010006ab2a2a0000002b0007063a3a03040303ff010001000005000501000000000023000" \
"044cd000500030268320010000e000c02683208687474702f312e31001b0003020002000a000c000a6a6a1" \
"1ec001d00170018000d001200100403080404010503080505010806060100000014001200000f617065782e" \
"6f7261636c652e636f6d003304ef04ed6a6a00010011ec04c0d85c00bada72320aa59ab72003bbbb06ca5d6" \
"173cc6c7883279c556fe9b4ac91bf35e66ad35590ef2176b74a323573a07e42ca13e94e7b823db1901ea7993" \
"291c4bcdde5066252834e65031aa9a572880ae9738c1d4067c05ac59300773476643cfc049e0a12113756192" \
"399a75a6e3619ad42e0b2149a77d1551cdaa30bdb1c89a0048975dcaf6b879f665370f3c7319f4271a265cc9" \
"510734b09c04b618e0c96cd805133d7208335b35f53c65470242315a38a32550cc4ac242b75573ca8a373d176f" \
"4635325f4a7186a9148d63e2d1230820050c2e1469ffc49320bad87d8c377f7187bb821626469bd2a587fd518d" \
"7c57349e58f4071078ae871fa1c805871a87fab5053c3059b969abab523d33206d4da5851f6a70d739e9395416da" \
"39effd07bd74901b950291b55cc3a347c406b58d547c587d62f5f327b52342bda676f572722a5b865df798292fa2" \
"94ebb483ff2c423f5142d51162822b4b93172a61b4440778569712b7dc74b6afa33e8458bad6912ef19463cc95741" \
"0a398208a349db84d8c750b9c4ac37ba3f54875c020978dac1c10adcb280922f8c5b4d57cc6dd1036a38591d91ab8a" \
"78f6008a0530c7c76c8d173c46a694af697cdf763d18572c99776a4440c8afe90fab928666e5046a2a921a313a750c" \
"9c48bc4ea860c6a9e251c1d941b712c7c0b5a4da9566440ab471053d9f14062c27939865498a75bc92538dddd4173f" \
"7b5c19e4783cfb70e745ac760b6867e72945e042fb096e3ca2547ecaa7f7b41feba1c94ff2041c34af9a08d06f3aaf" \
"7d654cf69450b6e4414a53ac2f749beb3c5c1d25b7f5b553e36061327c25093b1698aba71dea77fbbc9c7f49466b53c9" \
"376bc24f6b26e85a13c23a929998c1353b5c5926c033f372233a6263449483b5851457c867e7bc26617dbf5575ad346f2fab59c" \
"f0b21c51c786cc5366cf3ac167055ff27134f0b17ac18154aa6bde6340aa1003b74983525f2c1ae060c2a45190e0a87e24cb5f226" \
"9ce433171eba4a9cda4b34a5c5ca533e50bb7e69373df379a0fd3651054ba9153b3f36ab470b2709325891cad7083626b5a2448b28b" \
"3394f63b33a808cf0b0531b15024f042ed8b7c111323c377258aa75c13ae45937d627611c30e12b3cd48a332f17c0c320c9151214802" \
"49615f9685c252a12f50a4c890c243c80efc4b166cbbe0034317fdb59428c360dd78eeb533560e5b83994c99d994504e122ba2b78f72" \
"c1319d04124560f9072a2ca4b3957f90caa834ca4325f14dac9347493a7e731461a2d88e2c13e0034bea20a42c691ddaaa61ee2901c5" \
"557f9e0b239279ed2586bd3469e5205398ca5402aec072ff2564dc7ae5e9667aeaa4cbcf96bb8c8a3419041b7f641cee26d9f0bced784" \
"2cda7890b675386e543d5ae322bb53bb5606c3b8d44e6facc5b87b3f843c99dbf1882b43a89165861d3ba769735272a6175a858ee38a8" \
"1ae32173e3b538f1839c514919d6962263a7a8ad9800c2798cdea408c23165f1c8c59d782dcfa45d8857e1390b58540458713cd8d9a2e" \
"8ccbcfc472bb2e96213b06c281fc82afa76d04102a7b8a671b63afc35a98b9b22c59893a7047659f7609c6ab0206694fc5125ca13b4a8" \
"1593625afc57db06231534c6c1a767fd17876b7db9e7ac146b3f3f29a784565abc3744a78360bcec714475cdeb36b174fde0e5e00a866" \
"11ed78ddd8f1364f67001d0020529970babfbe868797b7529cc6ea7af39b264265f410f07f0457fbc86ba57b19fe0d011a0000010001a" \
"10020d7ab9c1847be9e4166c578cada94188dc391a95e99a8c69af12025266491332f00f0ae9c4eca218317b2c7cb4fcab828981b231c" \
"35615d0e8498d890c83e6de3d7c725d9f6a47ca3f53288ed7f0d24b67e491c8ecfd3e83ff8eead994889ed8373503bb1564a1b997a9d6" \
"5edd7ab240a88cef988f52df751b4214774486553848a51bbff0e7bf9c3e3f319df3aab801babdcf41e9e00e49c08855ab51eecea0bbf" \
"264191428576d65e5c249fa441b5dcb6e7534fec84704e918af08c4a40c7633e2d85321a9770b68b96107acfe1f0d4d636b35b1269c6f" \
"95173740edf4707dd8621a664525d7df9f6014bb66133a441e95d60fa129c47fef7ee1a28fc77c70bdf09a058cfbd54b9327dea0c6ea1" \
"8b9a59de00120000002d00020101000b0002010000170000aaaa000100")


# tls_real = TLSRecord(real_client_hello_wireshark)
# try:
#     tls_real.parse()
# except Exception as e:
#     print("Erroare de parsare", e)
# print(tls_real)