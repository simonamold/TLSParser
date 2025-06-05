import os
import sys
import signal
from parser.tls_record import TLSRecord 
from common.exceptions import *
from tools.test_data import *

def main():

    sample = bytes.fromhex(
    "16 03 01 00 43"                        # TLS Record Header (type: handshake, version: 1.0, length: 67)
    "01 00 00 3f"                          # Handshake Header (ClientHello, length: 63)
    "03 03"                                # ClientHello Version: TLS 1.2
    "5b 90 1c 84 53 2f 12 c7 4a 66 a2 1f 78 54 9b 78"     # Random (first half)
    "63b39e916d15af91f1334f0cd1874ef2"     # Random (second half)
    "00"                                   # Session ID length: 0
    "00 04"                                # Cipher Suites length: 4
    "00 2f 00 35"                          # Cipher Suites: TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
    "01"                                   # Compression Methods Length: 1
    "00"                                   # Compression Method: null
    "00 12"                                # Extensions length: 18
    "00 10"                                # Extension Type: ALPN (0x0010)
    "00 0e"                                # Extension Length: 14
    "00 10"                                # ALPN protocol name list length: 16
    "02 68 32"                             # Protocol 1: "h2"
    "08 68 74 74 70 2f 31 2e 31"  
    )

    ws_client_hello = bytes.fromhex("160301071d0100071903030620ffa650bedd452bf332a1f7432fa5f5e1da47de91551884a12dccdf29de9920d9aaea3200eb5cb4c4c05f53f7f7a1efed7b1d04516a3eba35f2aea48630dfe600203a3a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006b01a1a0000002b000706dada0304030300230000000500050100000000ff01000100003304ef04ed2a2a00010011ec04c0fc689487859242f2b24f2c92b90aaf1642bb47712918a97deb465ed98b3fc700101f1a5e322267196a5a682a5a6b011c1e84211824c36cec62d6884d82a1cb826bad7d457bf6b37e869a5b291881cc76aead8b06458282f1460b073206c1d71e939ac4876a1dfa2267d88b01d91caf0ca60d4184548fb7ba390a85604449004c3b8df53518f85b212b85e4195c05b921954bcb55f013a8d722de6093d34773a6a507f6e8bc3f744611b408a1a26b52b90aa3a0637518ce11e94949d45f88e948af7bcb25b32d5c946a7f6059512b7871a91a9fa6915a762592f66b020429045250b72c385187074d132b34b91de2975d8a285bd6c024da5013ec99ccc239b23cc0529e052f2c6959b4569be162545e561fb1929a5e4463a3550828f18fe6655f47f69db23bca35d0577729176468384feaa96a4346a506766150364f6647a50061a3e983f0669217ac925b621481abc70cda0be04b2929ebb008b0473d708f2adbb20872ccf0f45694003471c51f16b38f9b007f0c352d6d94b50ed412e7c61b7faa34c74914d1197ecd1806918309b4bb20a5ec0a134715ae87c461668bff8ca5cdd4abeef91082b38d58631a536a1f691a4dbe212380e15f532a91e8d24bb65b5fc10754880624ace8c7ae7933cdd6103968c733caaa2684a96455cf9c50948e971dd81c7e9e775525556f4407caafaac349c9c163f65f5c6bb8f093802562501c1a6c2a41683b0b13f645cf4be48fff22a7f7144a22b527389419134836501212698a3fde328975184a9c6a67f4914c50e26d1dd438c9c820eff073c5d11fba5926fd105668186bc11a1462416d1d242bca785981928ab3473299407df76a59c4c9a25330a4eb477e23a325712114b58931659c652560584eab1d18836c5ecc7ff57a558443ab02b077ef26962d22af58739665832b6a8b3f6df100c774018424344c9629400aa1e8a97b0ae67d997411d8a538fe2a49b7e7370cbc88a673b3f89561f748ace1b5712da7c49ab3c49b0209c6e03e608153c9b686d1911413479b1488a0448874b77486a7a191d1b54dcef10bd2a3a9d8ab984771bae270c2e0a19a1b792b98226321e2b0d8a78a6f768592a96e6a557e088a18d81b434b1133aaa478503c56111194b4192736fb5def40cf1c564c710c169045a17b2434507a2daa38b55649aa91768f988a0c09da387a148051e36d1bd39dbaf7607dca8ab2b33546869cbb328951b73728c98c1a6c61c746cf1d576391882d1c4ba729745424a2c5038b6548c4aa91a754a6ba233fcb61d657333aeb4747f4be649a658fcc96e5019538934538162f22c69f7da4856e2b934c5219db9829222738fcf49a1f76491ceb4294d7a92d981ce45cbd5b87965cba1bba18ae81e0314ad7bae41c78894147655304dc28a6abb271aa6149b8f78277e4402088ce8d198998b9ad7ddc18e5045bb8149f18ea1ec95619ba29cc05c91c434bcdbbdc766b276119f32c53c4b276d975167a35ead11d86b5a31873b1c39a575c0856d9a3b8d88549b6939a2cd32193710286f15b613ab6de467599e67a063031755956d7da5a94189caf513350e92cbe39890ce091176159a8671d63108dc93a77553bb962151ad37295e417af4407950c654a791e404d4b7ec9bcaa050a0faf3255ee5e30000ebdb74901afdbe718318d55016f5e6c09db4a77dad2d0c4a9289ad56bd10f1509b7fe65001d00204d03aa2719bb08173111e8bdb4975b4b861dba3cc712d8cb953f85570324894a0012000000170000000b0002010044cd00050003026832000d0012001004030804040105030805050108060601000a000c000a2a2a11ec001d001700180000001900170000147777772e776f6c6672616d616c7068612e636f6d002d00020101fe0d011a0000010001a60020242692fbd8790e20f6f268a9f4da497a69aa68484daba6826a9a7b25a647a42000f0d6e69f521d91e7b9de84d3a14d45ee222152debd94c51d106855013dce497c7da648af5e12f128de83a3042a68a5d9167b7a1c7e9995570378d5dfdf30da79430df4346e47e665fad562dd56c417a1b2d9cdeb51156392abb45a800e8cd1f990c8a5619e02b28da550bd727d6e50ef8974ac00a021fce5ef70494450d495ca2319c3c5a8581ab53a73307309dc7b6a7fd719c138ab3c0c3eb7bfe86e0362f96c8c6c0dedab6ce9b537a71e7938372feef7a0d85c29a67ca731392ad30d5deeaa656b20ba2642427d1dc5c95a17b3eec8d017847c8e51fd40348fcb027c83592ee9f6e03e3c58de8ac1303496bb2cc5120010000e000c02683208687474702f312e31001b00030200026a6a000100")
    wh_pac = TLSRecord(ws_client_hello)
    try:
        wh_pac.parse()
    except Exception as e:
        print("Parsing error: ", e)
    print(wh_pac)

    
    # test_sample = TLSRecord(sample)
    # try:
    #     test_sample.parse()
    # except Exception as e:
    #     print("Parsing error", e)
    #     sys.exit()
    #     signal.alarm(5)
    # print(test_sample)

    # for pkt in wireshark_packets:
    #     p = bytes.fromhex(pkt)
    #     packet = TLSRecord(p)
    #     try:
    #         packet.parse()
    #     except Exception as e:
    #         print("Parsing error: ", e)
    #     print(f"{packet} \n")
    # #test_tls_payload_parsing()

    # test_packets = []
    # test_packets.append(sample_alert)
    # test_packets.append(sample_css)
    # test_packets.append(sample_client_hello)
    # test_packets.append(sample_server_hello)
    
    # for pkt in client_hellos:
    #     packet = bytes.fromhex(pkt)
    #     test_packets.append(packet)
    # for pkt in server_hellos:
    #     packet = bytes.fromhex(pkt)
    #     test_packets.append(packet)
    # for pkt in truncated:
    #     packet = bytes.fromhex(pkt)
    #     test_packets.append(packet)
    # for pkt in wireshark_packets:
    #     packet = bytes.fromhex(pkt)
    #     test_packets.append(packet)

    # log_file = "tools/tls_parse_sample_data_results.txt"
    # with open(log_file, "w") as log:
    #     for index, value in enumerate(test_packets):
    #         packet = TLSRecord(value)
    #         log.write(f"----------Parsing packet no: {index} -----------\n")
    #         try:
    #             packet.parse()
    #             log.write(f"{packet} \n")
    #         except Exception as e:
    #             log.write(f"Failed to parse {index}: {e.__class__.__name__} - {e}")





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
