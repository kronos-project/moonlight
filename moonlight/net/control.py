"""
    Implementation of the KI control message protocol
"""

import logging
from argparse import ArgumentError
from dataclasses import dataclass
import struct
from typing import Any
from .common import (
    BytestreamReader,
    PacketHeader,
    Message,
    PACKET_HEADER_LEN,
    DMLType,
    MessageSender,
)
from moonlight.util import bytes_to_pretty_str

logger = logging.getLogger(__name__)


def _unpack_weirdo_timestamp(reader: BytestreamReader):
    # We have to store the bits in weird order due to KI's transmit pattern
    high_bits = reader.read(DMLType.UINT32)
    # FIXME: Hack for weird netpack framing
    while high_bits != 0:
        high_bits = reader.read(DMLType.UINT32)
    return struct.unpack("<I", reader.read_raw(4))[0]


@dataclass(init=True, repr=True, kw_only=True)
class ControlMessage(Message):
    OPCODE = None

    HUMAN_REPR_ORDER_PREPEND = (*Message.HUMAN_REPR_ORDER_PREPEND, "ctrl_type")

    session_id: int


@dataclass(init=True, repr=True, kw_only=True)
class SessionOfferMessage(ControlMessage):
    OPCODE = 0x0

    unix_timestamp_seconds: int
    unix_timestamp_millis_into_second: int
    signed_msg_len: int
    signed_msg: bytes

    def as_serde_dict(self) -> dict[str, Any] | Any:
        return {
            **super().as_serde_dict(),
            "data": {
                "format": "CONTROL",
                "name": type(self).__name__,
                "fields": {
                    "unix_timestamp_seconds": {
                        "value": self.unix_timestamp_seconds,
                        "format": "int",
                    },
                    "unix_timestamp_millis_into_second": {
                        "value": self.unix_timestamp_millis_into_second,
                        "format": "int",
                    },
                    "signed_msg": {
                        "value": bytes_to_pretty_str(self.signed_msg),
                        "format": "pretty bytes",
                    },
                },
            },
        }

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


@dataclass(init=True, repr=True, kw_only=True)
class SessionAcceptMessage(ControlMessage):
    OPCODE = 0x5

    reserved_start: int
    unix_timestamp_seconds: int
    unix_timestamp_millis_into_second: int
    signed_msg_len: int
    signed_msg: bytes

    def as_serde_dict(self) -> dict[str, Any] | Any:
        return {
            **super().as_serde_dict(),
            "data": {
                "format": "CONTROL",
                "name": type(self).__name__,
                "fields": {
                    "reserved_start": {
                        "value": self.reserved_start,
                        "format": "int",
                    },
                    "unix_timestamp_seconds": {
                        "value": self.unix_timestamp_seconds,
                        "format": "int",
                    },
                    "unix_timestamp_millis_into_second": {
                        "value": self.unix_timestamp_millis_into_second,
                        "format": "int",
                    },
                    "signed_msg": {
                        "value": bytes_to_pretty_str(self.signed_msg),
                        "format": "pretty bytes",
                    },
                },
            },
        }

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


@dataclass(init=True, repr=True, kw_only=True)
class KeepAliveMessage(ControlMessage):
    OPCODE = 0x3
    HUMAN_REPR_SYNTHETIC = {
        **ControlMessage.HUMAN_REPR_SYNTHETIC,
        "_client_min_into_session": lambda x: x.client_min_into_session()
        if x.sender is MessageSender.CLIENT
        else None,
        "_client_millis_into_second": lambda x: x.client_millis_into_second()
        if x.sender is MessageSender.CLIENT
        else None,
        "_server_millis_since_start": lambda x: x.server_millis_since_start()
        if x.sender is MessageSender.SERVER
        else None,
    }

    variable_timestamp: bytes

    def server_millis_since_start(self):
        return BytestreamReader(self.variable_timestamp).read(DMLType.UINT32)

    def client_millis_into_second(self):
        # bytes 1-2 hold if from client
        return BytestreamReader(self.variable_timestamp).read(DMLType.UINT16)

    def client_min_into_session(self):
        # bytes 3-4 hold if from client
        return BytestreamReader(self.variable_timestamp[2:]).read(DMLType.UINT16)

    def as_serde_dict(self) -> dict[str, Any] | Any:
        if self.sender is MessageSender.CLIENT:
            datafields = {
                "min_into_session": {
                    "value": self.client_min_into_session(),
                    "format": "int",
                },
                "millis_into_second": {
                    "value": self.client_millis_into_second(),
                    "format": "int",
                },
            }
        else:
            datafields = {
                "millis_since_start": {
                    "value": self.server_millis_since_start(),
                    "format": "int",
                }
            }
        return {
            **super().as_serde_dict(),
            "data": {
                "format": "CONTROL",
                "name": type(self).__name__,
                "fields": datafields,
            },
        }

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
        variable_timestamp = reader.read_raw(4)

        return cls(
            original_bytes=original_data,
            packet_header=packet_header,
            session_id=session_id,
            variable_timestamp=variable_timestamp,
        )


@dataclass(init=True, repr=True, kw_only=True)
class KeepAliveResponseMessage(KeepAliveMessage):
    """
    KeepAliveResponseMessage This is the response to the keep alive message.
    Structure is identical with a different OPCODE
    """

    OPCODE = 0x4


class ControlProtocol:
    """
    ControlProtocol Decoder capable of reading control messages from the Kingsisle Protocol
      These messages must be decrypted in order to be processed.
    """

    # TODO: refactor into function
    def decode_packet(  # pylint: disable=no-self-use
        self,
        bites: BytestreamReader | bytes,
        header: PacketHeader,
        original_data: bytes = None,
        has_ki_header: bool = True,
    ) -> ControlMessage:
        """
        decode_packet decodes a bytestring and represented header into its
          corresponding `ControlMessage`

        Args:
            bites (BytestreamReader | bytes): bytestring containing packet data
            header (PacketHeader): _description_
            original_data (bytes, optional): _description_. Defaults to None.
            has_ki_header (bool, optional): _description_. Defaults to True.

        Raises:
            ArgumentError: _description_
            ArgumentError: _description_

        Returns:
            ControlMessage: _description_
        """
        if not header.content_is_control:
            raise ArgumentError(
                header, message="PacketHeader is not for control packet"
            )
        opcode = header.control_opcode
        if opcode == SessionOfferMessage.OPCODE:
            return SessionOfferMessage.from_bytes(
                packet_header=header,
                reader=bites,
                original_bytes=original_data,
                has_ki_header=has_ki_header,
            )
        if opcode == SessionAcceptMessage.OPCODE:
            return SessionAcceptMessage.from_bytes(
                packet_header=header,
                reader=bites,
                original_data=original_data,
                has_ki_header=has_ki_header,
            )
        if opcode == KeepAliveMessage.OPCODE:
            return KeepAliveMessage.from_bytes(
                packet_header=header,
                reader=bites,
                original_data=original_data,
                has_ki_header=has_ki_header,
            )
        if opcode == KeepAliveResponseMessage.OPCODE:
            return KeepAliveResponseMessage.from_bytes(
                packet_header=header,
                reader=bites,
                original_data=original_data,
                has_ki_header=has_ki_header,
            )

        raise ArgumentError(header, message=f"Unrecognized opcode: {opcode}")
