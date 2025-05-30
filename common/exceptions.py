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
class TLSAlertError(Exception):
    """Base class for Alert parsing errors"""

class IncompleteAlertError(TLSAlertError):
    pass

class UnknownALertLevelError(TLSAlertError):
    pass

class UnknownALtertDescription(TLSAlertError):
    pass