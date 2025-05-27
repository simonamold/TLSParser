from enum import Enum

# As defined in RFC 8446 Section 4.2 https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2

class ExtensionType(Enum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    ALPN = 16  # Application Layer Protocol Negotiation
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51

    # Reserved but sometimes seen
    RENEGOTIATION_INFO = 65281  # 0xFF01