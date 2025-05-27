class TLSParserError(Exception):
    """Base class for parsing errors"""


# TLS Record
class TLSRecordError(TLSParserError):
    """Base class for TLS Record errors"""

class UnexpectedLength(TLSRecordError):
    pass

class IncompletePayloadError(TLSRecordError):
    pass

class UnknownTLSVersionError(TLSRecordError):
    pass

class UnknownTLSContentTypeError(TLSRecordError):
    pass

# TLS Handshake
class TLSHandshakeError(TLSParserError):
    """Base class for handshake parsing errors"""

class IncompleteHandshakeError(TLSHandshakeError):
    pass

class UnknownHandshakeTypeError(TLSHandshakeError):
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