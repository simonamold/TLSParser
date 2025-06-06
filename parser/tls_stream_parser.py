from io import BytesIO
import logging

from parser.tls_record import TLSRecord

logger = logging.getLogger(__name__)

class TLSStreamParser:
    def __init__(self, data: bytes):
        self.raw_data = data
        self.stream = BytesIO(self.raw_data)
        self.records = []
        self.errors =[]

    def parse(self):
        while self.stream.tell() < len(self.raw_data):

            # Rrecord header
            header = self.stream.read(5)
            if len(header) < 5:
                break

            # Extract length from header 
            length = int.from_bytes(header[3:5], 'big')

            # Read payload of that length
            payload = self.stream.read(length)
            if len(payload) < length:
                break

            raw_record = header + payload

            record = TLSRecord(raw_record)
            try:
                record.parse()
            except Exception as e:
                #print(f"TLS StreamParser error: {e}")
                logger.error("TLS StreamParser error", exc_info=True)
            self.records.append(record)


    
    def __str__(self, indent=0):
        pad = ' ' * indent
        lines = [f"{pad}TLS Stream:"]
        lines.append(f"{pad} Captured TLS records: {len(self.records)}")
        for i, record in enumerate(self.records):
            lines.append(f"{pad}  Record {i+1}:")
            lines.append(record.__str__(indent + 4))
        return '\n'.join(lines)