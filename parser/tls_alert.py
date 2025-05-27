from common.enums.alerts import AlertLevel , AlertDescription
from common.exceptions import *
from common.utils import EnumResolver

# 2 bytes
# -Alert Level
# -Alert Description


class TLSAlert:
    def __init__(self, raw_tls_record_payload : bytes):
        self.raw_alert = raw_tls_record_payload
        self.raw_alert_lvl = None
        self.raw_alert_descrption = None

        self.alert_lvl = None
        self.alert_description = None

    def parse(self):
        try:
            self.validate_alert(len(self.raw_alert))
        except IncompleteAlertError:
            pass
        if len(self.raw_alert) >= 1:
            self.raw_alert_lvl = self.raw_alert[0]
            try:
                self.alert_lvl = EnumResolver.parse(AlertLevel, self.raw_alert_lvl, exception_cls=UnknownALertLevelError)
            except UnknownALertLevelError:
                pass
        if len(self.raw_alert) >= 2:
            self.raw_alert_descrption = int.from_bytes(self.raw_alert[1:], 'big')
            try:
                self.alert_description = EnumResolver.parse(AlertDescription, self.raw_alert, exception_cls=UnknownALtertDescription)
            except UnknownALtertDescription:
                pass

    def validate_alert(self, length: int):
        if length < 2 or length > 2:
            raise IncompleteAlertError("Incomplete alert. Received: {length} bytes. Expected 2")
    

    def __str__(self):
        return (
            f"Alert Level= {self.alert_lvl or self.raw_alert_lvl}, "
            f"Description: {self.alert_description or self.raw_alert_descrption}"
        )
 