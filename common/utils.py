from io import BytesIO
from common.enums.tls_version import TLSVersion
from common.exceptions import TLSUnexpectedLengthError, UnknownTLSVersionError, TLSParserError

def validate_min_length(data: bytes, min_length: int, context: str = "Unknown"):
    if len(data) < min_length:
        raise TLSUnexpectedLengthError(f"{context} too short: expected min {min_length}, received {len(data)}")


class EnumResolver:
    @staticmethod
    def parse(enum_cls, raw_value, *, exception_cls=None):
        try:
            return enum_cls(raw_value)
        except ValueError:
            if exception_cls:
                raise exception_cls(f"Unknown {enum_cls.__name__} value : {raw_value}")
            

class VersionResolver:
    @staticmethod
    def get_version(major: int, minor : int):
        try:
            version_bytes = bytes([major, minor])
            return TLSVersion(version_bytes)
        except ValueError:
            raise UnknownTLSVersionError(
                f"Unknown TLS version:(0x{major:02x} 0x{minor:02x})"
            )
        

def read_exact(stream: BytesIO, n: int, field_name = "field") -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise TLSParserError(
            f"Incomplete read for {field_name}: expected {n}, received {len(data)}"
        )
    return data