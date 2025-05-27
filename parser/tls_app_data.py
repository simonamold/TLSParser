# Variable length encrypted data

class TLSAppData:
    def __init__(self, raw_tls_record_payload: bytes):
        self.data = raw_tls_record_payload
        
    def __str__(self):
        return f"Application data: {self.data}"