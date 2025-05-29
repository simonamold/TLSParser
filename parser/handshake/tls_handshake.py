from io import BytesIO
from common.enums.handshake_types import HandshakeType
from common.exceptions import *
from common.utils import EnumResolver
from .handshake_client_hello import ClientHello
from .handshake_server_hello import ServerHello

# Handshake header 4 bytes:
# - 1 Handshake type
# - 3 Length 


class TLSHandshake:
    TAG = "TLSHandshake"
    def __init__(self, raw_tls_record_payload : bytes):
        self.raw_handshake = raw_tls_record_payload
        self.raw_handshake_type = None
        self.length = None
        self.handshake_type = None
        self.raw_handshake_paylaod = None
        self.handshake_payload = None

    def parse_handshake(self):
        stream = BytesIO(self.raw_handshake)
        #print(f"Raw handshake len: {len(self.raw_handshake)}")
        try:
            self.validate_header(len(self.raw_handshake))
        except IncompleteHandshakeError: 
            pass

        if len(self.raw_handshake) >= 1:
            self.raw_handshake_type = int.from_bytes(stream.read(1), 'big')
            try:
                self.handshake_type = EnumResolver.parse(HandshakeType, self.raw_handshake_type, exception_cls=UnknownHandshakeTypeError)
            except UnknownHandshakeTypeError:
                pass
        if len(self.raw_handshake)>= 4:
            self.length = int.from_bytes(stream.read(3), 'big')

        if self.length is not None and len(self.raw_handshake) >= 4 + self.length:
            self.raw_handshake_paylaod = stream.read(self.length)

            match self.handshake_type:
                case HandshakeType.CLIENT_HELLO:
                    self.handshake_payload = ClientHello(self.raw_handshake_paylaod, self.handshake_type)
                    try:
                        self.handshake_payload.parse_client_hello()
                    except Exception as e:
                        print("Client Hello Error:", e)

                case HandshakeType.SERVER_HELLO:
                    self.handshake_payload = ServerHello(self.raw_handshake_paylaod, self.handshake_type)
                    try:
                        self.handshake_payload.parse_server_hello()
                    except Exception as e:
                        print("Server Hello Error:", e)

                case _:
                    print(f"[{self.TAG}] Unknown handshake type: {self.handshake_type}")
                    self.handshake_payload = None
            

    def validate_header(self, length: int):
        if length < 4:
            raise IncompleteHandshakeError("Incomplete header. Received: {length} bytes. Expected 5")


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
