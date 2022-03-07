"""
    Implementation of the KI control message protocol
"""


from .net_common import *
import struct


def _unpack_weirdo_timestamp(reader: BytestreamReader):
    # We have to store the bits in weird order due to KI's transmit pattern
    bitstring = b""
    high_bits = reader.read_raw(4)
    low_bits = reader.read_raw(4)
    bitstring = low_bits + high_bits
    return struct.unpack("<Q", bitstring)[0]


class ControlMessage(BaseMessage):
    OPCODE = None

    def __init__(self) -> None:
        pass


class SessionOfferMessage(ControlMessage, BaseMessageDecoder):
    OPCODE = 0x0

    def __init__(
        self,
        session_id: int,
        unix_timestamp_seconds: int,
        unix_timestamp_millis_into_second: int,
        signed_msg_len: int,
        signed_message: bytes,
        reserved: int,
    ) -> None:
        super().__init__()
        self.session_id: int = session_id
        self.unix_timestamp_seconds: int = unix_timestamp_seconds
        self.unix_timestamp_millis_into_second: int = unix_timestamp_millis_into_second
        self.signed_msg_len: int = signed_msg_len
        self.signed_msg: bytes = signed_message
        self.reserved = reserved

    def decode_message(
        reader: Union[BytestreamReader, bytes],
        original_data: bytes = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(HEADER_LEN)

        session_id = reader.read(DMLType.UINT16)
        sec_timestamp = _unpack_weirdo_timestamp(reader)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)
        signed_message_len = reader.read(DMLType.UINT32)
        signed_message = reader.read_raw(signed_message_len)
        reserved = reader.read(DMLType.UBYT)

        return SessionOfferMessage(
            session_id=session_id,
            unix_timestamp_seconds=sec_timestamp,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
            signed_msg_len=signed_message_len,
            signed_message=signed_message,
            reserved=reserved,
        )


class SessionAcceptMessage(ControlMessage, BaseMessageDecoder):
    OPCODE = 0x5

    def __init__(
        self,
        reserved_start: int,
        unix_timestamp_seconds: int,
        unix_timestamp_millis_into_second: int,
        session_id: int,
        signed_msg_len: int,
        signed_message: bytes,
        reserved_end: int,
    ) -> None:
        super().__init__()
        self.reserved_start: int = reserved_start
        self.unix_timestamp_seconds: int = unix_timestamp_seconds
        self.unix_timestamp_millis_into_second: int = unix_timestamp_millis_into_second
        self.session_id: int = session_id
        self.signed_msg_len: int = signed_msg_len
        self.signed_msg: bytes = signed_message
        self.reserved_end = reserved_end

    def decode_message(
        reader: Union[BytestreamReader, bytes],
        original_data: bytes = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(HEADER_LEN)

        reserved_start = reader.read(DMLType.UINT16)
        sec_timestamp = _unpack_weirdo_timestamp(reader)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)
        session_id = reader.read(DMLType.UINT16)
        signed_message_len = reader.read(DMLType.UINT32)
        signed_message = reader.read_raw(signed_message_len)
        reserved_end = reader.read(DMLType.UBYT)

        return SessionAcceptMessage(
            reserved_start=reserved_start,
            unix_timestamp_seconds=sec_timestamp,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
            session_id=session_id,
            signed_msg_len=signed_message_len,
            signed_message=signed_message,
            reserved_end=reserved_end,
        )


class KeepAliveMessage(ControlMessage, BaseMessageDecoder):
    OPCODE = 0x3

    def __init__(
        self,
        session_id: int,
        session_age_minutes: int,
        unix_timestamp_millis_into_second: int,
    ) -> None:
        super().__init__()
        self.session_id: int = session_id
        self.session_age_minutes: int = session_age_minutes
        self.unix_timestamp_millis_into_second: int = unix_timestamp_millis_into_second

    def decode_message(
        reader: Union[BytestreamReader, bytes],
        original_data: bytes = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(HEADER_LEN)

        session_id = reader.read(DMLType.UINT16)
        session_age_min = reader.read(DMLType.UINT32)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)

        return KeepAliveMessage(
            session_id=session_id,
            session_age_min=session_age_min,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
        )


class KeepAliveResponseMessage(KeepAliveMessage):
    """
    KeepAliveResponseMessage This is the response to the keep alive message.
    Structure is identical with a different OPCODE
    """

    OPCODE = 0x4

    def __init__(
        self,
        session_id: int,
        session_age_minutes: int,
        unix_timestamp_millis_into_second: int,
    ) -> None:
        super().__init__(
            self, session_id, session_age_minutes, unix_timestamp_millis_into_second
        )

    def decode_message(
        reader: Union[BytestreamReader, bytes],
        original_data: bytes = None,
        has_ki_header=False,
    ) -> ControlMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(HEADER_LEN)

        session_id = reader.read(DMLType.UINT16)
        session_age_min = reader.read(DMLType.UINT32)
        millis_into_sec_timestamp = reader.read(DMLType.UINT32)

        return KeepAliveResponseMessage(
            session_id=session_id,
            session_age_min=session_age_min,
            unix_timestamp_millis_into_second=millis_into_sec_timestamp,
        )


class ControlProtocol(MessageProtocol):
    def decode_packet(
        self,
        reader: Union[BytestreamReader, bytes],
        header: PacketHeader,
        original_data: bytes = None,
        **kwargs,
    ) -> BaseMessage:
        if not header.content_is_control:
            return None
        opcode = header.control_opcode
        if opcode == SessionOfferMessage.OPCODE:
            return SessionOfferMessage.decode_message(
                reader=reader, original_data=original_data
            )
        elif opcode == SessionAcceptMessage.OPCODE:
            return SessionAcceptMessage.decode_message(
                reader=reader, original_data=original_data
            )
        elif opcode == KeepAliveMessage.OPCODE:
            return KeepAliveMessage.decode_message(
                reader=reader, original_data=original_data
            )
        elif opcode == KeepAliveResponseMessage.OPCODE:
            return KeepAliveResponseMessage.decode_message(
                reader=reader, original_data=original_data
            )
        else:
            return None
