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
            self.raw_content_type = int.from_bytes(stream.read(1), 'big')
            #print(f"Raw content type {self.raw_content_type}")
            try:
                self.content_type = EnumResolver.parse(ContentType, self.raw_content_type, exception_cls=UnknownTLSContentTypeError)
            except UnknownTLSContentTypeError:
                pass
        if len(self.raw_packet) >= 3:
            self.raw_major_ver = int.from_bytes(stream.read(1), 'big')
            self.raw_minor_ver = int.from_bytes(stream.read(1), 'big')

            try:
                self.version = VersionResolver.get_version(self.raw_major_ver, self.raw_minor_ver)
            except UnknownTLSVersionError:
                pass
       
        if len(self.raw_packet) >= 5:
            self.length = int.from_bytes(stream.read(2), 'big')

        if self.length is not None and len(self.raw_packet) >= 5 + self.length:
            self.raw_payload = stream.read(self.length)
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


    def __str__(self, indent=0):
        pad = ' ' * indent
        parts = [
            f"{pad}TLSRecord:",
            f"{pad}  content_type = {self.content_type}",
            f"{pad}  version      = {self.version}",
            f"{pad}  length       = {self.length}",
            f"{pad}  fragment     ="
        ]
        parts.append(self.payload.__str__())
        return "\n".join(parts)

