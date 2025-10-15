from dataclasses import dataclass
import struct
@dataclass
class IPPacket:
    """Encapsulates IP packet"""
    version: int
    header_length: int
    total_length: int
    protocol: int
    src_ip: str
    dst_ip: str
    payload: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        """Parse IP packet"""
        if len(data) < 20:
            raise ValueError("Incomplete IP header")

        version_ihl = data[0]
        if isinstance(version_ihl, str):
            # Converts string byte to integer
            version_ihl = ord(version_ihl)

        # Extract version and IHL
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        total_length = struct.unpack('!H', data[2:4])[0]
        protocol = data[9]
        if isinstance(protocol, str):
            # Converts string byte to integer
            protocol = ord(protocol)

        src_ip = '.'.join(str(b) for b in data[12:16])
        dst_ip = '.'.join(str(b) for b in data[16:20])

        payload = data[ihl:]

        return cls(version, ihl, total_length, protocol,
                   src_ip, dst_ip, payload)