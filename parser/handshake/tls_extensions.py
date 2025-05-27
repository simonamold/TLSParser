from dataclasses import dataclass
from io import BytesIO
from common.utils import read_exact

"""
    RFC 8446 - 4.2
    RFC 5246 - 7.4.1.4
struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension;
"""
@dataclass
class TLSExtension:
    extension_type: int
    extension_length: int
    extension_data: bytes


class TLSExtensions():

    def __init__(self, stream: BytesIO):
        self.stream = stream
        self.extensions = []

    def parse(self):

        print(f"TLS Extensions: cursor: {self.stream.tell()}")
        extensions_length = int.from_bytes(read_exact(self.stream, 2, 'extension_length'), 'big')
        print(f"EXtension cls: extension lenght= {extensions_length}")
        
        end = self.stream.tell() + extensions_length

        while self.stream.tell() < end:
            extension_type = int.from_bytes(read_exact(self.stream, 2, 'extension_type'), 'big')

            print(f"TLS Extensions: extension type= {extension_type}")
            
            extension_length = int.from_bytes(read_exact(self.stream, 2, 'extension_length'), 'big')
            
            print(f"TLS Extensions: extension length= {extension_length}")
            
            extension_data = read_exact(self.stream, extension_length, f'extension_data (type= {extension_type})')
            
            print(f"TLS Extensions: extension data= {extension_data}")

            self.extensions.append(TLSExtension(extension_type, extension_length, extension_data))


    def __str__(self):
        return (
            f"TLS Extensions count= {len(self.extensions)}"
        )