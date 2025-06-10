class TLSParserError(Exception):
    """Base class for parsing errors"""

class TLSUnexpectedLengthError(TLSParserError):
    pass

class TLSUnknownVersionError(TLSParserError):
    pass

class TLSUnknownContentTypeError(TLSParserError):
    pass

class TLSUnknownHandshakeTypeError(TLSParserError):
    pass

class TLSUnknownExtensionTypeError(TLSParserError):
    pass

class TLSUndeclaredCipherSuite(TLSParserError):
    pass

# TLS Alert

class UnknownALertLevelError(TLSParserError):
    pass

class UnknownALtertDescription(TLSParserError):
    pass