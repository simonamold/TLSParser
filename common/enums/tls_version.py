from enum import Enum

# As defined at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5


class TLSVersion(Enum):
    SSL3 = b'\x03\x00'
    TLS_1_0 = b'\x03\x01'
    TLS_1_1 = b'\x03\x02'
    TLS_1_2 = b'\x03\x03'
    TLS_1_3 = b'\x03\x04'