from common.enums.cipher_suites import CipherSuites
from common.exceptions import TLSParserError
from parser.handshake.tls_extensions import TLSExtensions
from parser.handshake.tls_hello_message import BaseHello
from common.utils import EnumResolver, read_exact

# Server Hello Structure  RFC 8446
#   server_version 2 bytes
#   random 32 bytes
#   session_is_length 1 byte
#   session_id <0...32> byes
#   cipher_suite 2 bytes 
#   uint8 compression_method  = 0
#   extensions <8...2^16-1> optional


class ServerHello(BaseHello):
    TAG = "ServerHello"
    def __init__(self, handshake_payload : bytes, handshake_type: int):
        super().__init__(handshake_payload, handshake_type)

        self.cipher_suite = None
        self.compression_meth = None
        self.extensions_total_length = None
        self.extensions = None

    def parse_server_hello(self):
        self.parse_common_fields()

        cipher_suite_bytes = read_exact(self.stream, 2, "cipher_suite")
        
        try:
            self.cipher_suite = EnumResolver.parse(CipherSuites, cipher_suite_bytes, exception_cls=Exception)
        except TLSParserError as e:    
            print("Server Hello ", e)
            
        self.compression_meth = read_exact(self.stream, 1, "compression_method")
        
        # EXtensions
        
        #print("1")
        #print(f"Stream position before TLSExtensions parse: {self.stream.tell()}")
        if self.stream.tell() < len(self.raw_hello_msg):
            #print("2")
            #self.extensions_total_length = int.from_bytes(read_exact(self.stream,2,'extension_total_length'), 'big')
            
            #print(f"Stream position before TLSExtensions parse 2: {self.stream.tell()}")
            self.extensions = TLSExtensions(self.stream, self.handshake_type)
            self.extensions.parse()
        # else:
        #     print("Ceva nu e OK")
    

    def __str__(self, indent=0):
        pad = ' ' * indent
        parts = [
            f"{pad}ClientHello:",
            f"{pad}  version        = {self.version}",
            f"{pad}  random         = {self.random.hex()}",
            f"{pad}  session_id     = {self.session_id.hex()}",
            f"{pad}  cipher_suite   = {self.cipher_suite}",
            f"{pad}  compression    = {self.compression_meth}",
        ]
        if self.extensions:
            parts.append(self.extensions.__str__(indent + 2))
        return "\n".join(parts)
    

