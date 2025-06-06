from io import BytesIO
import logging
from common.utils import VersionResolver
from common.exceptions import *

""""
    Base class for the Client Hello and Server Hello
    client/server version 2 bytes
    random 32 bytes
    session_is_length 1 byte
    session_id <0...32> byes
"""
logger = logging.getLogger(__name__)

class BaseHello:
    TAG = "[ BaseHello ]"
    def __init__(self, raw_data: bytes, handshake_type: int, error_list=None):
        self.is_valid = True
        self.errors = error_list if error_list is not None else []
        
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
        self.raw_major_ver = int.from_bytes(self.stream.read(1), 'big')
        self.raw_minor_ver = int.from_bytes(self.stream.read(1), 'big')
        try:
            self.version = VersionResolver.get_version(self.raw_major_ver, self.raw_minor_ver)
        except TLSUnknownVersionError as e:
            self.is_valid = False
            self.errors.append(str(e))
            #print(f"{self.TAG} Version parsing error: {e}")
            logger.error("Version parsing error", exc_info=True)
            self.version = bytes(self.raw_major_ver, self.raw_minor_ver)
 
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