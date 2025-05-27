from enum import Enum

# As defined at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5

    
class HandshakeType(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20