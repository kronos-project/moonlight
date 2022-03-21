"""
    Implementation of the KI control message protocol
"""


import struct

from .common import *


def _unpack_weirdo_timestamp(reader: BytestreamReader):
    # We have to store the bits in weird order due to KI's transmit pattern
    bitstring = b""
    high_bits = reader.read_raw(4)
    low_bits = reader.read_raw(4)
    bitstring = low_bits + high_bits
    return struct.unpack("<Q", bitstring)[0]


class ControlMessage:
    OPCODE = None

    def __init__(self, packet_header: PacketHeader, original_bytes: bytes) -> None:
        self.packet_header = packet_header
        self.original_bytes = original_bytes


class SessionOfferMessage(ControlMessage):
    OPCODE = 0x0

    def __init__(
        self,
        packet_header: PacketHeader,
        original_bytes: bytes,
        session_id: int,
        unix_timestamp_seconds: int,
        unix_timestamp_millis_into_second: int,
        signed_msg_len: int,
        signed_message: bytes,
    ) -> None:
        super().__init__(packet_header, original_bytes)
        self.session_id: int = session_id
        self.unix_timestamp_seconds: int = unix_timestamp_seconds
        self.unix_timestamp_millis_into_second: int = unix_timestamp_millis_into_second
        self.signed_msg_len: int = signed_msg_len
        self.signed_msg: bytes = signed_message

    @classmethod
    def from_bytes(
        cls,
        reader: Union[BytestreamReader, bytes],
        original_bytes: bytes = None,
        packet_header: PacketHeader = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(PACKET_HEADER_LEN)

        session_id = reader.read(DMLType.UINT16)
        sec_timestamp = _unpack_weirdo_timestamp(reader)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)
        signed_message_len = reader.read(DMLType.UINT32)
        signed_message = reader.read_raw(signed_message_len)
        if not reader.at_packet_terminate():
            raise ValueError("packet did not end with a null byte")

        return cls(
            original_bytes=original_bytes,
            packet_header=packet_header,
            session_id=session_id,
            unix_timestamp_seconds=sec_timestamp,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
            signed_msg_len=signed_message_len,
            signed_message=signed_message,
        )


class SessionAcceptMessage(ControlMessage):
    OPCODE = 0x5

    def __init__(
        self,
        packet_header: PacketHeader,
        original_bytes: bytes,
        reserved_start: int,
        unix_timestamp_seconds: int,
        unix_timestamp_millis_into_second: int,
        session_id: int,
        signed_msg_len: int,
        signed_message: bytes,
    ) -> None:
        super().__init__(packet_header, original_bytes)
        self.reserved_start: int = reserved_start
        self.unix_timestamp_seconds: int = unix_timestamp_seconds
        self.unix_timestamp_millis_into_second: int = unix_timestamp_millis_into_second
        self.session_id: int = session_id
        self.signed_msg_len: int = signed_msg_len
        self.signed_msg: bytes = signed_message

    @classmethod
    def from_bytes(
        cls,
        reader: Union[BytestreamReader, bytes],
        original_data: bytes = None,
        packet_header: PacketHeader = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(PACKET_HEADER_LEN)

        reserved_start = reader.read(DMLType.UINT16)
        sec_timestamp = _unpack_weirdo_timestamp(reader)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)
        session_id = reader.read(DMLType.UINT16)
        signed_message_len = reader.read(DMLType.UINT32)
        signed_message = reader.read_raw(signed_message_len)
        if not reader.at_packet_terminate():
            raise ValueError("packet did not end with a null byte")

        return cls(
            original_bytes=original_data,
            packet_header=packet_header,
            reserved_start=reserved_start,
            unix_timestamp_seconds=sec_timestamp,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
            session_id=session_id,
            signed_msg_len=signed_message_len,
            signed_message=signed_message,
        )


class KeepAliveMessage(ControlMessage):
    OPCODE = 0x3

    def __init__(
        self,
        packet_header: PacketHeader,
        original_bytes: bytes,
        session_id: int,
        session_age_minutes: int,
        unix_timestamp_millis_into_second: int,
    ) -> None:
        super().__init__(packet_header, original_bytes)
        self.session_id: int = session_id
        self.session_age_minutes: int = session_age_minutes
        self.unix_timestamp_millis_into_second: int = unix_timestamp_millis_into_second

    @classmethod
    def from_bytes(
        cls,
        reader: Union[BytestreamReader, bytes],
        original_data: bytes = None,
        packet_header: PacketHeader = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(PACKET_HEADER_LEN)

        session_id = reader.read(DMLType.UINT16)
        session_age_minutes = reader.read(DMLType.UINT32)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)
        if reader.bytes_remaining != 1 or reader.read_raw(1) != 0x0:
            raise ValueError("packet did not end with a null byte")

        return cls(
            original_bytes=original_data,
            packet_header=packet_header,
            session_id=session_id,
            session_age_minutes=session_age_minutes,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
        )


class KeepAliveResponseMessage(KeepAliveMessage):
    """
    KeepAliveResponseMessage This is the response to the keep alive message.
    Structure is identical with a different OPCODE
    """

    OPCODE = 0x4


class ControlProtocol:
    def decode_packet(
        self,
        reader: Union[BytestreamReader, bytes],
        header: PacketHeader,
        original_data: bytes = None,
        has_ki_header: bool = False,
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
