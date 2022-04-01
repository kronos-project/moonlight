"""
    Implementation of the KI control message protocol
"""


from dataclasses import dataclass
import struct
from typing import Union
from .common import BytestreamReader, PacketHeader, PACKET_HEADER_LEN, DMLType


def _unpack_weirdo_timestamp(reader: BytestreamReader):
    # We have to store the bits in weird order due to KI's transmit pattern
    bitstring = b""
    high_bits = reader.read_raw(4)
    low_bits = reader.read_raw(4)
    bitstring = low_bits + high_bits
    return struct.unpack("<Q", bitstring)[0]


# FIXME: session id is for all control and should be here
@dataclass(init=True, repr=True)
class ControlMessage:
    OPCODE = None

    packet_header: PacketHeader
    original_bytes: bytes

    def to_human_dict(self):
        return {
            "packet_header": self.packet_header.to_human_dict(),
            "original_bytes": self.original_bytes,
        }


@dataclass(init=True, repr=True)
class SessionOfferMessage(ControlMessage):
    OPCODE = 0x0

    session_id: int
    unix_timestamp_seconds: int
    unix_timestamp_millis_into_second: int
    signed_msg_len: int
    signed_msg: bytes

    @classmethod
    def from_bytes(
        cls,
        reader: BytestreamReader | bytes,
        original_bytes: bytes = None,
        packet_header: PacketHeader = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if isinstance(reader, bytes):
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(PACKET_HEADER_LEN)

        session_id = reader.read(DMLType.UINT16)
        sec_timestamp = _unpack_weirdo_timestamp(reader)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)
        signed_msg_len = reader.read(DMLType.UINT32)
        signed_msg = reader.read_raw(signed_msg_len)

        return cls(
            original_bytes=original_bytes,
            packet_header=packet_header,
            session_id=session_id,
            unix_timestamp_seconds=sec_timestamp,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
            signed_msg_len=signed_msg_len,
            signed_msg=signed_msg,
        )

    def to_human_dict(self):
        data = vars(self)
        data.update(super().to_human_dict())
        return data


@dataclass(init=True, repr=True)
class SessionAcceptMessage(ControlMessage):
    OPCODE = 0x5

    reserved_start: int
    unix_timestamp_seconds: int
    unix_timestamp_millis_into_second: int
    session_id: int
    signed_msg_len: int
    signed_msg: bytes

    @classmethod
    def from_bytes(
        cls,
        reader: BytestreamReader | bytes,
        original_data: bytes = None,
        packet_header: PacketHeader = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if isinstance(reader, bytes):
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(PACKET_HEADER_LEN)

        reserved_start = reader.read(DMLType.UINT16)
        sec_timestamp = _unpack_weirdo_timestamp(reader)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)
        session_id = reader.read(DMLType.UINT16)
        signed_message_len = reader.read(DMLType.UINT32)
        signed_message = reader.read_raw(signed_message_len)

        return cls(
            original_bytes=original_data,
            packet_header=packet_header,
            reserved_start=reserved_start,
            unix_timestamp_seconds=sec_timestamp,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
            session_id=session_id,
            signed_msg_len=signed_message_len,
            signed_msg=signed_message,
        )

    def to_human_dict(self):
        data = vars(self)
        data.update(super().to_human_dict())
        return data


@dataclass(init=True, repr=True)
class KeepAliveMessage(ControlMessage):
    OPCODE = 0x3

    session_id: int
    variable_timestamp: bytes

    def server_millis_since_start(self):
        return BytestreamReader(self.variable_timestamp).read(DMLType.UINT32)

    def client_millis_into_second(self):
        # bytes 1-2 hold if from client
        return BytestreamReader(self.variable_timestamp).read(DMLType.UINT16)

    def client_min_into_session(self):
        # bytes 3-4 hold if from client
        return BytestreamReader(self.variable_timestamp[2:]).read(DMLType.UINT16)

    def to_human_dict(self):
        data = vars(self)
        data.update(super().to_human_dict())
        return data

    @classmethod
    def from_bytes(
        cls,
        reader: BytestreamReader | bytes,
        original_data: bytes = None,
        packet_header: PacketHeader = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if isinstance(reader, bytes):
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(PACKET_HEADER_LEN)

        session_id = reader.read(DMLType.UINT16)
        variable_timestamp = reader.read(DMLType.UINT32)

        return cls(
            original_bytes=original_data,
            packet_header=packet_header,
            session_id=session_id,
            variable_timestamp=variable_timestamp,
        )


@dataclass(init=True, repr=True)
class KeepAliveResponseMessage(KeepAliveMessage):
    """
    KeepAliveResponseMessage This is the response to the keep alive message.
    Structure is identical with a different OPCODE
    """

    OPCODE = 0x4


class ControlProtocol:
    def decode_packet(
        self,
        reader: BytestreamReader | bytes,
        header: PacketHeader,
        original_data: bytes = None,
        has_ki_header: bool = True,
    ) -> ControlMessage:
        if not header.content_is_control:
            return None
        opcode = header.control_opcode
        if opcode == SessionOfferMessage.OPCODE:
            return SessionOfferMessage.from_bytes(
                packet_header=header,
                reader=reader,
                original_bytes=original_data,
                has_ki_header=has_ki_header,
            )
        if opcode == SessionAcceptMessage.OPCODE:
            return SessionAcceptMessage.from_bytes(
                packet_header=header,
                reader=reader,
                original_data=original_data,
                has_ki_header=has_ki_header,
            )
        if opcode == KeepAliveMessage.OPCODE:
            return KeepAliveMessage.from_bytes(
                packet_header=header,
                reader=reader,
                original_data=original_data,
                has_ki_header=has_ki_header,
            )
        if opcode == KeepAliveResponseMessage.OPCODE:
            return KeepAliveResponseMessage.from_bytes(
                packet_header=header,
                reader=reader,
                original_data=original_data,
                has_ki_header=has_ki_header,
            )

        return None
