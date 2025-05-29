from common.enums.cipher_suites import CipherSuites
from common.exceptions import *
from parser.handshake.tls_extensions import TLSExtensions
from parser.handshake.tls_hello_message import BaseHello
from common.utils import EnumResolver, read_exact

# Client Hello Structure  RFC 8446
#   client_version 2 bytes
#   random 32 bytes
#   session_is_length 1 byte
#   session_id <0...32> byes
#   cipher_suites_length 2 bytes
#   cipher_suites <2...2^16-2>
#   compression_method <1....2^8-1>  -> legacy TLS 1.3 no longer allow compression
#   extensions <8...2^16-1> optional


class ClientHello(BaseHello):
    TAG = "ClientHello"
    def __init__(self, handshake_payload: bytes, handshake_type: int):
        super().__init__(handshake_payload, handshake_type)

        self.cipher_suites_length = None
        self.cipher_suites = []
        self.compression_meth_length = None
        self.compression_meth = None
        self.extensions_total_length = None
        self.extensions = []

    def parse_client_hello(self):

        self.parse_common_fields()

        cipher_suite_len_bytes = read_exact(self.stream, 2, "cipher_suites_length")
        self.cipher_suites_length = int.from_bytes(cipher_suite_len_bytes, 'big')

        cipher_suites_bytes = read_exact(self.stream, self.cipher_suites_length, "cipher_suites")
        if len(cipher_suites_bytes) % 2 != 0:
            raise TLSParserError("Uneven cipher suites length")
        

        for i in range(0, self.cipher_suites_length, 2):
            suite_bytes = cipher_suites_bytes[i:i+2]
            # suite_int = int.from_bytes(suite_bytes, 'big')
            try:
                suite = EnumResolver.parse(CipherSuites, suite_bytes, exception_cls=Exception)
            except Exception as e:
                print("Error la suites", e)
                suite = None  
            self.cipher_suites.append(suite)


        self.compression_meth_length = int.from_bytes(read_exact(self.stream, 1, "compression_methods_length"), "big")
        self.compression_meth = read_exact(self.stream, self.compression_meth_length, "compression_methods")

        # Extensions 

        if self.stream.tell() < len(self.raw_hello_msg):
            #self.extensions_total_length = int.from_bytes(read_exact(self.stream,2,'extension_total_length'), 'big')
            self.extensions = TLSExtensions(self.stream, self.handshake_type)
            self.extensions.parse()
        

    def __str__(self, indent=0):
        pad = ' ' * indent
        parts = [
            f"{pad}ClientHello:",
            f"{pad}  version        = {self.version}",
            f"{pad}  random         = {self.random.hex()}",
            f"{pad}  session_id     = {self.session_id.hex()}",
            f"{pad}  cipher_suites  = {self.cipher_suites}",
            f"{pad}  compression    = {self.compression_meth}",
        ]
        if self.extensions:
            parts.append(self.extensions.__str__(indent + 2))
        return "\n".join(parts)
