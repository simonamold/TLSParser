from io import BytesIO
from common.enums.alerts import AlertLevel , AlertDescription
from common.exceptions import *
from common.utils import EnumResolver, validate_min_length

# 2 bytes
# -Alert Level
# -Alert Description


class TLSAlert:
    TAG = "[ TLS Alert ]"
    def __init__(self, raw_tls_record_payload : bytes):
        self.is_valid = True
        self.errors = []

        self.raw_alert = raw_tls_record_payload
        self.raw_alert_lvl = None
        self.raw_alert_descrption = None

        self.alert_lvl = None
        self.alert_description = None

    def parse(self):
        stream = BytesIO(self.raw_alert)
        try:
            validate_min_length(self.raw_alert, 2, context=self.TAG)
        except TLSUnexpectedLengthError as e:
            self.is_valid = False
            self.errors[str(e)]
            print(f"{self.TAG} Packet dropped: {e}")
            return
        
        self.raw_alert_lvl = int.from_bytes(stream.read(1), 'big')
        try:
            self.alert_lvl = EnumResolver.parse(AlertLevel, self.raw_alert_lvl, exception_cls=UnknownALertLevelError)
        except UnknownALertLevelError as e:
            self.is_valid = False
            self.errors[str(e)]
            self.alert_lvl = self.raw_alert_lvl
            print(f"{self.TAG} Alert Level parsing error: {e}")
              
        
        self.raw_alert_descrption = int.from_bytes(stream.read(1), 'big')
        try:
            self.alert_description = EnumResolver.parse(AlertDescription, self.raw_alert_descrption, exception_cls=UnknownALtertDescription)
        except UnknownALtertDescription:
            self.is_valid = False
            self.errors[str(e)]
            self.alert_description = self.raw_alert_descrption
            print(f"{self.TAG} Alert Description parsing error: {e}")
    

    def __str__(self, indent=0):
        pad = ' ' * indent
        parts = [
            f"{pad}TLSAlert:",
            f"{pad}  alert_level        = {self.alert_lvl}",
            f"{pad}  alert_description  = {self.alert_description}",
        ]
        return "\n".join(parts)


       