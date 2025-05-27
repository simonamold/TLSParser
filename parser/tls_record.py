# TO DO: proper validations 
# I am testing the parser with a mismatched length and it fails both to parse or store


from io import BytesIO
from common.enums.content_types import ContentType

from common.exceptions import *
from common.utils import EnumResolver, VersionResolver
from .handshake.tls_handshake import TLSHandshake
from .tls_alert import TLSAlert
from .tls_change_cipher_spec import TLSChangeCipherSpe
from .tls_app_data import TLSAppData

# Record structure:
# - content type = 1 byte
# - version = 2 bytes
# - length = 2 bytes max 2^14
# Ex = \x16\x03\x03\x00\x31

"""
    Considerations regarding the implementation:
    - I initially wanted to make length and value validations directly in th constructure
    - I realised I cannot instantiate the object without  trawing exceptions if the packet is malformed
    - I dedided to store the byte sequence as it enters and parse it separately
    - I thought about using placeholders in case I receive a malformed packet, basically to imitate the correct structure, however that could be problematic
    - 
"""
TAG = "TLSRecord cls: "

class TLSRecord:
    TAG = "TLSRecord"
    def __init__(self, raw_bytes: bytes):
        self.raw_packet = raw_bytes
        self.raw_content_type = None
        self.raw_major_ver = None
        self.raw_minor_ver = None
        self.raw_payload = None

        self.content_type = None
        self.version = None
        self.length = None
        self.payload = None

    def parse(self):
        stream = BytesIO(self.raw_packet)
        try:
            self.validate_header(len(self.raw_packet))   
        except UnexpectedLength:
            pass
        if len(self.raw_packet) >= 1:
            # self.raw_content_type = self.raw_packet[0]
            # print(f"Raw content type {self.raw_content_type}")
            self.raw_content_type = int.from_bytes(stream.read(1), 'big')
            #print(f"Raw content type {self.raw_content_type}")
            try:
                self.content_type = EnumResolver.parse(ContentType, self.raw_content_type, exception_cls=UnknownTLSContentTypeError)
            except UnknownTLSContentTypeError:
                pass
        if len(self.raw_packet) >= 3:
            # self.raw_major_ver = self.raw_packet[1]
            # self.raw_minor_ver = self.raw_packet[2]
            self.raw_major_ver = int.from_bytes(stream.read(1), 'big')
            self.raw_minor_ver = int.from_bytes(stream.read(1), 'big')

            try:
                self.version = VersionResolver.get_version(self.raw_major_ver, self.raw_minor_ver)
            except UnknownTLSVersionError:
                pass
       
        if len(self.raw_packet) >= 5:
            #self.length = int.from_bytes(self.raw_packet[3:5], 'big')
            self.length = int.from_bytes(stream.read(2), 'big')

        if self.length is not None and len(self.raw_packet) >= 5 + self.length:
            #self.raw_payload = self.raw_packet[5:5+self.length]
            self.raw_payload = stream.read(self.length)
            print(f"raw payload: {self.raw_payload}")
            match self.content_type:
                case ContentType.HANDSHAKE:
                    self.payload = TLSHandshake(self.raw_payload)
                    try:
                        self.payload.parse_handshake()
                    except Exception as e:
                        print("Record Error:", e)

                case ContentType.ALERT:
                    self.payload = TLSAlert(self.raw_payload)
                    try:
                        self.payload.parse()
                    except TLSParserError:
                        self.payload = None

                case ContentType.CHANGE_CIPHER_SPEC:  
                    self.payload = TLSChangeCipherSpe(self.raw_payload)
                    try:
                        self.payload.parse()
                    except TLSParserError:
                        self.payload = None

                case ContentType.APPLICATION_DATA:
                    self.payload = TLSAppData(self.raw_payload)

                case _:
                    print(f"[{self.TAG}] Unknown content type: {self.content_type}")
                    self.payload = None

        
    def validate_header(self, length: int):
        if length < 5:
            raise UnexpectedLength("Incomplete header. Received: {length} bytes. Expected 5")

    def __str__(self):
        return (
            f"TLSRecord:\n"
            f"content_type= {self.content_type or self.raw_content_type}, \n"
            f"version= {self.version} \n"
            f"length= {self.length}, \n"
            f"fragment= {self.payload}"
        )