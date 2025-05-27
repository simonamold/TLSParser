from common.enums.cipher_suites import CipherSuites
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
    def __init__(self, handshake_payload : bytes):
        super().__init__(handshake_payload)

        self.cipher_suite = None
        self.compression_meth = None
        self.extensions_total_length = None
        self.extensions = None

    def parse_server_hello(self):
        self.parse_common_fields()

        cipher_suite_bytes = read_exact(self.stream, 2, "cipher_suite")
        
        try:
            self.cipher_suite = EnumResolver.parse(CipherSuites, cipher_suite_bytes, exception_cls=Exception)
        except Exception as e:    
            print("Error la suites", e)
            
        self.compression_meth = read_exact(self.stream, 1, "compression_method")
        
        print("1")
        print(f"Stream position before TLSExtensions parse: {self.stream.tell()}")
        if self.stream.tell() < len(self.raw_hello_msg):
            print("2")
           # self.extensions_total_length = int.from_bytes(read_exact(self.stream,2,'extension_total_length'), 'big')
            
            print(f"Stream position before TLSExtensions parse 2: {self.stream.tell()}")
            self.extensions = TLSExtensions(self.stream)
            self.extensions.parse()
        else:
            print("Ceva nu e OK :))")
    

    def __str__(self):
        #base_info = super().__str__()
        return(
            f"Version: {self.version}\n"
            f"Random: {self.random.hex() if self.random else None}\n"
            f"Session ID Length: {self.session_id_length}\n"
            f"Session ID: {self.session_id if self.session_id else None}\n"
            f"Cipher Suite: {self.cipher_suite} \n"
            f"Compression Methods: {self.compression_meth}\n"
            f"Extensions: {self.extensions.__str__()}"
            #f"{base_info}\n"
            #f"Cipher Suites Length: {self.cipher_suites_length}\n"
            #f"Cipher Suites: {[cs.name if hasattr(cs, 'name') else hex(cs) for cs in self.cipher_suites]}\n"
            #f"Compression Methods Length: {self.compression_meth_length}\n"
            #f"Compression Methods: {self.compression_meth}\n"
            #f"Extensions: {[ext.extension_type.name if hasattr(ext.extension_type, 'name') else ext.extension_type for ext in self.extensions]}"
        )

