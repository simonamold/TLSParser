from common.enums.cipher_suites import CipherSuites
from common.exceptions import TLSParserError, TLSUndeclaredCipherSuite
from parser.handshake.tls_extensions import TLSExtensions
from parser.handshake.tls_hello_message import BaseHello
from common.utils import EnumResolver, read_exact
import logging

# Server Hello Structure  RFC 8446
#   server_version 2 bytes
#   random 32 bytes
#   session_is_length 1 byte
#   session_id <0...32> byes
#   cipher_suite 2 bytes 
#   uint8 compression_method  = 0
#   extensions <8...2^16-1> optional

logger = logging.getLogger(__name__)

class ServerHello(BaseHello):
    TAG = "[ Server Hello ]"
    def __init__(self, handshake_payload : bytes, handshake_type: int, error_list=None):
        super().__init__(handshake_payload, handshake_type, error_list)

        self.cipher_suite = None
        self.compression_meth = None
        self.extensions_total_length = None
        self.extensions = None

    def parse_server_hello(self):

        self.parse_common_fields()

        try:

            cipher_suite_bytes = read_exact(self.stream, 2, "cipher_suite")
            
            try:
                self.cipher_suite = EnumResolver.parse(CipherSuites, cipher_suite_bytes, exception_cls=TLSUndeclaredCipherSuite)
            except TLSUndeclaredCipherSuite as e:    
                self.errors.append(str(e))
                #print(f"{self.TAG} Cipher Suite parsing error: {e}")
                logger.error("Cipher Suite parsing error", exc_info=True)
                self.cipher_suite = cipher_suite_bytes
                
            self.compression_meth = read_exact(self.stream, 1, "compression_method")
        except TLSParserError as e:
            self.is_valid = False
            self.errors.append(str(e))
            #print(f"{self.TAG} : {e}")
            logger.error("ServerHello parsing error", exc_info=True)
        # EXtensions
        
        if self.stream.tell() < len(self.raw_hello_msg):
            
            self.extensions = TLSExtensions(self.stream, self.handshake_type)
            self.extensions.parse()
       
    
    def __str__(self, indent=0):
        pad = ' ' * indent
        parts = [
            f"{pad}ServerHello:",
            f"{pad}  version        = {self.version.name if hasattr(self.version, "name") else self.version} "
            f"({self.version.value if hasattr(self.version, "value") else self.version})",
            f"{pad}  random         = {self.random.hex()}",
            f"{pad}  session_id     = {self.session_id.hex()}",
            f"{pad}  cipher_suite   = {self.cipher_suite if hasattr(self.cipher_suite, "name") else self.cipher_suite} "
            f"({self.cipher_suite.value if hasattr(self.cipher_suite, "value") else self.cipher_suite})",
            f"{pad}  compression    = {self.compression_meth}",
        ]
        if self.extensions:
            parts.append(self.extensions.__str__(indent + 2))
        return "\n".join(parts)
    

