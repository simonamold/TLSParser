from enum import Enum

# As defined at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5

class ContentType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23