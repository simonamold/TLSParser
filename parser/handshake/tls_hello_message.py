from io import BytesIO
from common.utils import VersionResolver
from common.exceptions import *

""""
    Base class for the Client Hello and Server Hello
    client/server version 2 bytes
    random 32 bytes
    session_is_length 1 byte
    session_id <0...32> byes
"""
TAG = "BaseHello cls: "
class BaseHello:
    def __init__(self, raw_data: bytes, handshake_type: int):
        self.raw_hello_msg = raw_data
        self.handshake_type = handshake_type
        self.stream = BytesIO(self.raw_hello_msg)

        self.raw_major_ver = None
        self.raw_minor_ver = None
        self.version = None
        self.random = None
        self.session_id_length = None
        self.session_id = None

    def parse_common_fields(self):
        #print(f"Raw hello msg len: {len(self.raw_hello_msg)}")

        # self.raw_major_ver = self.raw_hello_msg[0]
        # self.raw_minor_ver = self.raw_hello_msg[1]
        self.raw_major_ver = int.from_bytes(self.stream.read(1), 'big')
        self.raw_minor_ver = int.from_bytes(self.stream.read(1), 'big')
        try:
            self.version = VersionResolver.get_version(self.raw_major_ver, self.raw_minor_ver)
        except UnknownTLSVersionError:
            pass
        
        # self.random = self.raw_hello_msg[2:34] # 2:34
        # self.session_id_length = self.raw_hello_msg[34] # 34
        # self.session_id = self.raw_hello_msg[35:35+self.session_id_length]

        self.random = self.stream.read(32)
        self.session_id_length = int.from_bytes(self.stream.read(1),'big')
        self.session_id = self.stream.read(self.session_id_length)

    def __str__(self):
        return (
            f"Version: {self.version}\n"
            f"Random: {self.random.hex() if self.random else None}\n"
            f"Session ID Length: {self.session_id_length}\n"
            f"Session ID: {self.session_id.hex() if self.session_id else None}"
        )