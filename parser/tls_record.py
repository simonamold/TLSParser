from io import BytesIO
import logging
from common.enums.content_types import ContentType
from common.exceptions import *
from common.utils import EnumResolver, VersionResolver, validate_declared_length, validate_min_length
from .handshake.tls_handshake import TLSHandshake
from .tls_alert import TLSAlert
from .tls_change_cipher_spec import TLSChangeCipherSpe
from .tls_app_data import TLSAppData

# Record structure:
# - content type = 1 byte
# - version = 2 bytes
# - length = 2 bytes max 2^14
# Ex = \x16\x03\x03\x00\x31

logger = logging.getLogger(__name__)

class TLSRecord:
    TAG = "[ TLS Record ]"
    def __init__(self, raw_bytes: BytesIO):
        self.is_valid = True
        self.errors = []

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

        # Check the header length and drop the pachet if < 5
        try:
            validate_min_length(self.raw_packet, 5, context=self.TAG)
        except TLSUnexpectedLengthError as e:
            self.is_valid = False
            self.errors.append(str(e))
            logger.error("Packet dropped", exc_info=True)
            return
        
        
        
        self.raw_content_type = int.from_bytes(stream.read(1), 'big')
        #print(f"Raw content type {self.raw_content_type}")
        try:
            self.content_type = EnumResolver.parse(
                ContentType, 
                self.raw_content_type, 
                exception_cls=TLSUnknownContentTypeError)
        except TLSUnknownContentTypeError as e:
            self.is_valid = False
            self.errors.append(str(e))
            logger.error("Content type parsing error", exc_info=True)
            #print(f"{self.TAG} Content type parsing error: {e}")
            self.content_type = self.raw_content_type
        
        self.raw_major_ver = int.from_bytes(stream.read(1), 'big')
        self.raw_minor_ver = int.from_bytes(stream.read(1), 'big')

        try:
            self.version = VersionResolver.get_version(
                self.raw_major_ver, 
                self.raw_minor_ver)
        except TLSUnknownVersionError as e:
            self.is_valid = False
            self.errors.append(str(e))
            #print(f"{self.TAG} Version parsing error: {e}")
            logger.error("Version parsing error", exc_info=True)
            self.version = bytes([self.raw_major_ver, self.raw_minor_ver])
    
        
        self.length = int.from_bytes(stream.read(2), 'big')

        try:
            validate_declared_length(self.raw_packet, self.length, header_length=5, context=self.TAG)
            self.raw_payload = stream.read(self.length)
            try:
                match self.content_type:
                    case ContentType.HANDSHAKE:
                        self.payload = TLSHandshake(self.raw_payload, error_list=self.errors)
                        self.payload.parse_handshake()

                    case ContentType.ALERT:
                        self.payload = TLSAlert(self.raw_payload)
                        self.payload.parse()

                    case ContentType.CHANGE_CIPHER_SPEC:  
                        self.payload = TLSChangeCipherSpe(self.raw_payload)
                        self.payload.parse()

                    case ContentType.APPLICATION_DATA:
                        self.payload = TLSAppData(self.raw_payload)

                    case _:
                        #print(f"[{self.TAG}] Unknown content type: {self.content_type}")
                        self.payload = None
            except TLSParserError as e:
                self.is_valid = False
                self.errors.append(str(e))
                #print(f"{self.TAG} Payload parsing error: {e}")
                logger.error("Payload parsing error", exc_info=True)

        except TLSUnexpectedLengthError as e:
            self.is_valid = False
            self.errors.append(str(e))
            #print(f"{self.TAG} Payload length validation error: {e}")
            logger.error("Payload length validation error", exc_info=True)
        
    

    def __str__(self, indent=0):
        pad = ' ' * indent
        cont_type = self.content_type.name if hasattr(self.content_type, "name") else self.content_type
        ver = self.version.name if hasattr(self.version, "name") else self.version
        parts = [
            f"{pad}TLSRecord:",
            f"{pad}  content_type = {self.content_type.name if hasattr(self.content_type, "name") else self.content_type} "
            f"({self.content_type.value if hasattr(self.content_type, "value") else self.content_type})",
            f"{pad}  version      = {self.version.name if hasattr(self.version, "name") else self.version} "
            f"({self.version.value if hasattr(self.version, "value") else self.version})",
            f"{pad}  length       = {self.length}",
            f"{pad}  fragment     ="
        ]
        parts.append(self.payload.__str__())
        return "\n".join(parts)

