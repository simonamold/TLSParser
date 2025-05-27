from common.exceptions import TLSParserError

""" - 1 byte - 0x01 -> The cange cipher suite message
    - signls switch to encrypted communication in TLS 1.2 and earlier verions
    - TLS 1.3 for compatibility 
"""

class TLSChangeCipherSpe:
    def __init__(self, raw_tls_record_payload):
        self.raw_ccs = raw_tls_record_payload
        self.css_message = None

    def parse(self):
        try:
            self.validate_ccs_length(len(self.raw_ccs))
        except TLSParserError:
            pass

        self.css_message = self.raw_ccs[0]
        try:
            self.validate_ccs_value(self.css_message)
        except TLSParserError:
            pass


    def validate_ccs_length(self, length: int):
        if length is None or length > 1 :
            raise TLSParserError("Unxepected lenght: {length} bytes. Expected 1")
        
    def validate_ccs_value(self, byte: bytes):
        if byte != b'\x01' :
            raise TLSParserError("Unxepected value: {byte} bytes. Expected {b'\x01'}")
        
    def __str__(self):
        return(
            f"Change Cipher Spec Message= {self.css_message or self.raw_ccs}"
        )