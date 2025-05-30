from io import BytesIO
from common.enums.handshake_types import HandshakeType
from common.exceptions import *
from common.utils import EnumResolver, validate_min_length, validate_declared_length
from .handshake_client_hello import ClientHello
from .handshake_server_hello import ServerHello

# Handshake header 4 bytes:
# - 1 Handshake type
# - 3 Length 


class TLSHandshake:
    TAG = "[ TLS Handshake ]"
    def __init__(self, raw_tls_record_payload : bytes, error_list=None):
        self.is_valid = True
        self.errors = error_list if error_list is not None else []

        self.raw_handshake = raw_tls_record_payload
        self.raw_handshake_type = None
        self.length = None
        self.handshake_type = None
        self.raw_handshake_paylaod = None
        self.handshake_payload = None

    def parse_handshake(self):
        stream = BytesIO(self.raw_handshake)  
        #print(f"Raw handshake len: {len(self.raw_handshake)}")

        # Check the header length and drop the pachet if < 4
        try:
            validate_min_length(self.raw_handshake, 4, context=self.TAG)
        except TLSUnexpectedLengthError as e:
            self.is_valid = False
            self.errors[str(e)]
            print(f"{self.TAG} Packet dropped: {e}")
            return

        self.raw_handshake_type = int.from_bytes(stream.read(1), 'big')

        try:
            self.handshake_type = EnumResolver.parse(
                HandshakeType, 
                self.raw_handshake_type, 
                exception_cls=TLSUnknownContentTypeError)
        except TLSUnknownHandshakeTypeError as e:
            self.is_valid = False
            self.errors.append(str(e))
            print(f"{self.TAG} Handshake type parsing error: {e}")
            self.handshake_type = self.raw_handshake_type

        self.length = int.from_bytes(stream.read(3), 'big')

        try:
            validate_declared_length(self.raw_handshake, self.length, header_length=4, context=self.TAG)
            self.raw_handshake_paylaod = stream.read(self.length)

            try:
                match self.handshake_type:
                    case HandshakeType.CLIENT_HELLO:

                        """ 
                            Min Client Hello 42 bytes:
                        2 ver + 32 random + 1 ses id len 
                        + 2 cipher suite len + 2 at least 1 cipher suite 
                        + 2 compre meth
                        """
                        try:
                            validate_min_length(self.raw_handshake_paylaod, 42, context={self.TAG + "Client Hello length"})
                        except TLSUnexpectedLengthError as e:
                            self.is_valid = False
                            self.errors.append(str(e))
                            print(f"{self.TAG} Client Hello length validation error: {e}")

                        self.handshake_payload = ClientHello(self.raw_handshake_paylaod, self.handshake_type, self.errors)
                        self.handshake_payload.parse_client_hello()

                    case HandshakeType.SERVER_HELLO:

                        """ 
                            Min Server Hello 38 bytes:
                        2 ver + 32 random + 1 ses id len 
                        + 2 cipher suite 
                        + 1 compre meth
                        """
                        try:
                            validate_min_length(self.raw_handshake_paylaod, 38, context={self.TAG + "Server Hello length"})
                        except TLSUnexpectedLengthError as e:
                            self.is_valid = False
                            self.errors.append(str(e))
                            print(f"{self.TAG} Server Hello length validation error: {e}")

                        self.handshake_payload = ServerHello(self.raw_handshake_paylaod, self.handshake_type, self.errors)
                        self.handshake_payload.parse_server_hello()

                    case _:
                        print(f"{self.TAG} Unknown handshake type: {self.handshake_type}")
                        self.handshake_payload = None
            except TLSParserError as e:
                self.is_valid = False
                self.errors.append(str(e))
                print("f{self.TAG} Handshake payload parsing error: {e}")
        except TLSUnexpectedLengthError as e:
            self.is_valid = False
            self.errors.append(str(e))
            print(f"{self.TAG} Payload length validation error: {e}")


    def __str__(self, indent=0):
        pad = ' ' * indent
        parts = [
            f"{pad}TLSHandshake:",
            f"{pad}  handshake_type = {self.handshake_type}",
            f"{pad}  length         = {self.length}",
        ]
        if self.handshake_payload:
            parts.append(f"{pad}  payload:")
            parts.append(self.handshake_payload.__str__(indent + 4))
        return "\n".join(parts)
