from enum import Enum
from io import BytesIO
from common.enums.tls_version import TLSVersion
from common.exceptions import TLSUnexpectedLengthError, TLSUnknownVersionError, TLSParserError

def validate_min_length(data: bytes, min_length: int, context: str = "Unknown"):
    if len(data) < min_length:
        raise TLSUnexpectedLengthError(
            f"{context} too short: expected min {min_length}, received {len(data)}"
        )

def validate_declared_length(data: bytes, declare_length: int, header_length: int = 0, context: str = "Unknown"):
    total_required = header_length + declare_length
    actual_received = len(data)

    if actual_received < total_required:
        raise TLSUnexpectedLengthError(
            f"{context} declared lenght= {declare_length} "
            f"received {actual_received - header_length}"
        )

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
            raise TLSUnknownVersionError(
                f"Unknown TLS version:(0x{major:02x} 0x{minor:02x})"
            )
        

def read_exact(stream: BytesIO, n: int, field_name = "field") -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise TLSParserError(
            f"Incomplete read for {field_name}: expected {n}, received {len(data)}"
        )
    return data

def format_cipher_suites(items, indent=0):
    pad = ' ' * indent
    lines = []
    for item in items:
        if isinstance(item, Enum):
            lines.append(f"{pad}- {item.name} ({item.value.hex()})")
        elif isinstance(item, dict):
            lines.append(f"{pad}-")
            for k, v in item.items():
                lines.append(f"{pad}    {k}: {v}")
        else:
            lines.append(f"{pad}- {str(item)}")
    return "\n".join(lines)
