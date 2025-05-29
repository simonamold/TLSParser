from dataclasses import dataclass
from io import BytesIO
from typing import Any
from common.enums.handshake_types import HandshakeType
from common.enums.tls_extension_types import ExtensionType
from common.exceptions import TLSParserError
from common.utils import EnumResolver, VersionResolver, read_exact
from common.constants import KEY_SHARE_NAMED_GROUPS, SIGNATURE_SCHEMES

"""
    RFC 8446 - 4.2
    RFC 5246 - 7.4.1.4
struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension;
"""
class TLSExtensions():

    def __init__(self, stream: BytesIO, handshake_type: int):
        self.stream = stream
        self.handshake_type = handshake_type
        self.extensions = []

    def parse(self):
        extensions_length = int.from_bytes(read_exact(self.stream, 2, 'extension_length'), 'big')

        end = self.stream.tell() + extensions_length

        while self.stream.tell() < end:
            raw_extension_type = int.from_bytes(read_exact(self.stream, 2, 'extension_type'), 'big')
            try:
                extension_type = EnumResolver.parse(ExtensionType, raw_extension_type, exception_cls=TLSParserError)
            except TLSParserError:
                extension_type = raw_extension_type
            extension_length = int.from_bytes(read_exact(self.stream, 2, 'extension_length'), 'big')  
            extension_data = read_exact(self.stream, extension_length, f'extension_data (type= {extension_type})')

            extension = TLSExtension(extension_type, extension_length, extension_data)
            
            # print(f"Extension type: {extension_type}")
            # print(f"Extension type value {ExtensionType.SUPPORTED_VERSIONS.value}")
            if extension_type == ExtensionType.SUPPORTED_VERSIONS:
                extension.parsed = extension.extract_supported_versions(extension_data, self.handshake_type)
            
            elif extension_type == ExtensionType.SERVER_NAME:
                extension.parsed = extension.extract_server_name(extension_data, self.handshake_type)

            elif extension_type == ExtensionType.KEY_SHARE:
                extension.parsed = extension.extract_key_share(extension_data, self.handshake_type)

            elif extension_type == ExtensionType.SUPPORTED_GROUPS:
                extension.parsed = extension.extract_supported_groups(extension_data)

            elif extension_type == ExtensionType.SIGNATURE_ALGORITHMS:
                extension.parsed = extension.extract_signature_algorithm(extension_data)
            
            elif extension_type == ExtensionType.PSK_KEY_EXCHANGE_MODES:
                extension.parsed = extension.extract_psk_key_exchange_modes(extension_data)
            self.extensions.append(extension)


    def __str__(self, indent=0):
        pad = ' ' * indent
        lines = [f"{pad}Extensions count: {len(self.extensions)}"]
        for ext in self.extensions:
            lines.append(ext.__str__(indent + 2))
        return "\n".join(lines)
    


@dataclass
class TLSExtension:
    extension_type: int
    extension_length: int
    extension_data: bytes
    parsed: Any = None


    """
        SUPPORTED_VERSIONS
        Client Hello: 1 byte length + 2 byte supported versions list
        Server Hello: selected version
    """
    @staticmethod
    def extract_supported_versions(data: bytes, handshake_type: int):
        if not data:
            return []
        versions = []

        if handshake_type == HandshakeType.CLIENT_HELLO:
            length = data[0]
            if len(data) < 1 + length:
                raise ValueError("Incomplete extensions in Client Hello")
            for i in range(1, 1 + length, 2):
                ver_major = data[i]
                ver_minor = data[i+1]
                try:
                    version = VersionResolver.get_version(ver_major, ver_minor)
                except Exception:
                    version = (ver_major, ver_minor)
                versions.append(version)

        elif handshake_type == HandshakeType.SERVER_HELLO:
            if len(data) < 2:
                raise ValueError("Incomplete Extensionin Server Hello")
            ver_major = data[0]
            ver_minor = data[1]
            try:
                version = VersionResolver.get_version(ver_major, ver_minor)
            except Exception:
                version = (ver_major, ver_minor)
            versions.append(version)

        else:
            raise ValueError(f"Unsupported handshake type: {handshake_type}")
        
        return versions
    
    """
        SERVER_NAME
        RFC 6066 Section 3
        - 2 byets server_name_list length
        - 1 byte name type
        - 2 bytes name length
        - name 
    """
    @staticmethod
    def extract_server_name(data: bytes, handshake_type: int):
        stream = BytesIO(data)
        if handshake_type != HandshakeType.CLIENT_HELLO:
            raise ValueError("Not applicable")
        if len(data) < 5:
            raise ValueError("Invalid server_name format")
        total_length = int.from_bytes(stream.read(2))
        names = []

        while stream.tell() < total_length:
            name_type = stream.read(1)
            name_length = int.from_bytes(stream.read(2), 'big')
            name_bytes = stream.read(name_length)
            try:
                name = name_bytes.decode('utf-8')
            except UnicodeDecodeError:
                name = name_bytes.hex()
            names.append({'type ': name_type, 'name ': name})
        return names
    
    """
        KEY_SHARE
        Client Hello: - multiple key_shares can be sent
            - 2 bytes -> client_shares_length
            - 2 bytes -> group
            - 2 bytes -> key_lenght
            - variable lenght -> key_exchange
        Server Hello: one key_share
            - 2 bytes -> group
            - 2 bytes -> key_lenght
            - variable lenght -> key_exchange
    """
    @staticmethod
    def extract_key_share(data: bytes, handshake_type:int):
        stream = BytesIO(data)
        key_shares = []

        if handshake_type == HandshakeType.CLIENT_HELLO:
            if len(data) < 2:
                raise ValueError("Key Share extension too short in CLient Hello")
            total_length = int.from_bytes(stream.read(2), 'big')
            while stream.tell() <= total_length:
                group = int.from_bytes(stream.read(2), 'big')
                key_length = int.from_bytes(stream.read(2), 'big')
                if len(data) < total_length + 2: #
                    raise ValueError("Incomplete key_exchange field in Cleint Hello")
                key_exchange = stream.read(key_length)

                key_shares.append({
                    "group ": group,
                    "group_name": KEY_SHARE_NAMED_GROUPS.get(group, f"Unknown ({group})"),
                    "key_exchange": key_exchange.hex()
                })
        elif handshake_type == HandshakeType.SERVER_HELLO:
            if len(data) < 4:
                raise ValueError("Key Share extension to short in Server Hello")
            group = int.from_bytes(stream.read(2), 'big')
            key_length = int.from_bytes(stream.read(2), 'big')
            if len(data) < key_length + 2: #
                raise ValueError("Incomplete key_exchange field in Server Hello")
            
            key_exchange = stream.read(key_length)
            key_shares.append({
                    "group ": group,
                    "group_name": KEY_SHARE_NAMED_GROUPS.get(group, f"Unknown ({group})"),
                    "key_exchange": key_exchange.hex()
                })
        else:
            raise ValueError(f"Unsupported handshake typw: {handshake_type}")
        return key_shares
    
    """
        SUPPORTED_GROUPS
        - 2 bytes length
        - group identifiers (2 bytes each)
    """
    @staticmethod
    def extract_supported_groups(data:bytes):
        stream = BytesIO(data)
        groups = []
        if len(data) < 2:
            raise ValueError("Extension is too short")
        total_length = int.from_bytes(stream.read(2), 'big')
        groups_bytes = stream.read(total_length)
        if len(data) < 2 + total_length:
            raise ValueError("Incomplete suppored groups list")
        for i in range(0, total_length, 2):
            group_id = int.from_bytes(groups_bytes[i:i+2], 'big')
            group_name = KEY_SHARE_NAMED_GROUPS.get(group_id, f"Unknown ({group_id})")
            groups.append(group_name)
        return groups
    
    """
        SIGNATURE_ALGORITHMS
        - 2 bytes length of the list
        - the list (2 bytes each algorithm)
    """
    @staticmethod
    def extract_signature_algorithm(data:bytes):
        stream = BytesIO(data)
        algorithms = []
        if len(data) < 2:
            raise ValueError("Incomplete signature_algorithm extension")
        
        total_length = int.from_bytes(stream.read(2), 'big')
        
        algorithm_bytes = stream.read(total_length)
        if len(data) < 2 + total_length:
            raise ValueError("Signature algorithm list incomplete")
        for i in range(0, total_length, 2):
            scheme_id = int.from_bytes(algorithm_bytes[i:i+2], 'big')
            name = SIGNATURE_SCHEMES.get(scheme_id, f"Unknown (0x{scheme_id:04x})")
            algorithms.append(name)
    
        return algorithms

    """
        PSK_KEY_EXCHANGE_MODES
        - 1 byte length
        - list of modes (1 byte each)
        - 2 mode described by IANA:
            -0x00: psk_ke
            -0x01: psk_dhe_ke
    """
    @staticmethod
    def extract_psk_key_exchange_modes(data:bytes):
        stream = BytesIO(data)
        modes = []
        if len(data) < 2:
            raise ValueError("Incomplete psk_key_exchange_modes extension")

        total_length = int.from_bytes(stream.read(1), 'big')
        nodes_bytes = stream.read(total_length)
        if len(data) != 1 + total_length:
            raise ValueError("Mismatched psk_key_exchange_modes length")
        for i in range(total_length):
            mode = nodes_bytes[i]
            if mode == 0:
                modes.append("psk_ke")
            elif mode == 1:
                modes.append("psk_dhe_ke")
            else:
                modes.append(f"unknown (0x{mode:02x})")

        return modes

    def __str__(self, indent=0):
        pad = ' ' * indent
        ext_type = self.extension_type.name if hasattr(self.extension_type, "name") else self.extension_type
        parsed_str = self.parsed if isinstance(self.parsed, str) else repr(self.parsed)
        return (
            f"{pad}Extension Type: {ext_type}\n"
            f"{pad}  Length    : {self.extension_length}\n"
            f"{pad}  Raw Data  : {self.extension_data.hex()}\n"
            f"{pad}  Parsed    : {parsed_str}"
        )
