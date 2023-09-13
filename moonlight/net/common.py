"""Shared stuff between the KI network protocol"""

from __future__ import annotations
import contextlib
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import struct
from io import BytesIO
from typing import Any, cast

from moonlight.util import SerdeMixin, bytes_to_pretty_str

PACKET_HEADER_LEN = 8
DML_HEADER_LEN = 2


class MessageSender(SerdeMixin, Enum):
    """Represents one of the various creators of a message within
    Wizard101 and/or the kronos toolkit.
    """

    CLIENT = 1
    SERVER = 2
    FLAGTOOL = 3

    def __init__(self, sender) -> None:
        self.netpack_port = sender

    def as_serde_dict(self, **kwargs) -> dict[str, Any] | Any:
        return self.name

    @classmethod
    def from_capture_port(cls, port: int) -> MessageSender | None:
        """Get sender via pcap destination port

        Gets the sender enum based on the netpack capture
        synthetic port. These numbers are based off the storing netpack
        client's implementation (moonlight being libnetpack)

        Args:
            port (int): port number of the packet sender

        Returns:
            MessageSender | None: representing enum if exists, otherwise `None`
        """
        for const in cls:
            if const.netpack_port == port:
                return const
        return None


@dataclass(init=True, repr=True, kw_only=True)
class Message(SerdeMixin):
    """Base message type

    Message is the base type of all message implementations in moonlight.
    Extend it to create new types of messages.
    """

    original_bytes: bytes | None
    ki_header: KIHeader | None = None
    sender: MessageSender | None = None
    timestamp: datetime | None = None

    def as_serde_dict(self, **kwargs) -> dict[str, Any] | Any:
        """
        See `moonlight.util.SerdeMixin#as_serde_dict`
        """
        # Override as we are doing more than the mixin is intended for
        return {
            "sender": None
            if self.sender is None
            else self.sender.as_serde_dict(**kwargs),
            "timestamp": None if self.timestamp is None else self.timestamp.isoformat(),
            "raw": bytes_to_pretty_str(self.original_bytes),
        }


class DMLType(SerdeMixin, Enum):
    """Bit types used by the KI network protocol.

    Args:
        name (str): Name used in encodings. Same as the enum names.
        length (int): Number of bytes used in the initial read for the field.
            For an encoding of a set length, this is the entire
            length of the field. For encodings that start with
            a length byte(s), this is the length of the length
            field.
        struct_code (str): Format string for the python struct.unpack
            method that will take the initial read bytes
            and convert them into the python type.
            For an encoding of a set length, this initial
            read is the entire length of the field. For
            encodings that start with a length byte(s),
            this is the unpack code of that byte(s). The
            remainder is handled by the BytestreamReader
            as a special case.
    """

    # Basic types
    BOOL = ("bool", 1, "<?")
    INT8 = ("int8", 1, "<b")
    UINT8 = ("uint8", 1, "<B")
    INT16 = ("int16", 2, "<h")
    UINT16 = ("uint16", 2, "<H")
    INT32 = ("int32", 4, "<i")
    UINT32 = ("uint32", 4, "<I")
    FLOAT32 = ("float32", 4, "<f")
    FLOAT64 = ("float64", 8, "<d")
    UINT64 = ("uint64", 8, "<q")
    # TODO lol i forgot int64

    # DML specific
    BYT = ("BYT", 1, "<b")  # int8
    UBYT = ("UBYT", 1, "<B")  # uint8
    SHRT = ("SHRT", 2, "<h")  # int16
    USHRT = ("USHRT", 2, "<H")  # uint16
    INT = ("INT", 4, "<i")  # int32
    UINT = ("UINT", 4, "<I")  # uint32
    FLT = ("FLT", 4, "<f")  # float32
    DBL = ("DBL", 8, "<d")  # float64
    GID = ("GID", 8, "<q")  # uint64
    # uint16 length definition followed by utf8
    STR = (
        "STR",
        2,
        "<H",
    )
    # uint16 length definition followed by utf8 encoding a PropertyObject
    # TODO: Deprecate and remove
    PO_STR = (
        "PO_STR",
        2,
        "<H",
    )
    # uint16 length definition followed by utf16 LE
    WSTR = ("WSTR", 2, "<H")
    # uint16 length definition followed by utf16 LE encoding a PropertyObject
    PO_WSTR = ("PO_WSTR", 2, "<H")

    def __init__(self, t_name, length, struct_code):
        """
        Args:
            t_name (str): name of the encoding type
            length (int): length of the encoded information.
               For some types, this may instead represent the size of the
               length prefix. See implementation in `BytestreamReader`
            struct_code (str): `struct.unpack`'s structure code
        """
        self.t_name = t_name
        self.length = length
        self.struct_code = struct_code

    @classmethod
    def from_str(cls, t_name_: str| None) -> DMLType | None:  # sourcery skip: use-next
        """String representation to DMLType

        Enum described by the given string or `None` if invalid

        Args:
            t_name (str): The enum's name.

        Returns:
            DMLType | None: enum described by the given string or `None` if invalid
        """
        if t_name_ is None:
            return None
        for enum in cls:
            if enum.t_name.upper() == t_name_.upper():
                return enum
        return None

    def as_serde_dict(self, **kwargs) -> dict[str, Any] | Any:
        """
        See `SerdeMixin#as_serde_dict`
        """
        return self.t_name

    def __str__(self):
        return self.t_name

    def __repr__(self) -> str:
        return f"<DMLType.{self.t_name}>"


class BytestreamReader:
    """Byte reading utility with `DMLType` integration

    Wrapper of BufferedReader used to simplify reading bytestrings
    into their standard type value. Accepts any DMLType not prefaced
    with a length. Otherwise, you'll need to modify this as a special
    case.
    """

    def __init__(self, bites: bytes) -> None:
        """Initializes a BytestreamReader with a bytestring

        Args:
            bites (bytes): bytestring to add to buffer
        """
        self.stream = BytesIO(bites)

    def read_raw(self, length, peek=False) -> bytes:
        """Reads the given number of bytes off the string

        Args:
            length (int): number of bytes to read. If not provided, reads all.
            peek (bool, optional): True if reading leaves the bytes in
              the buffer. Defaults to False.
        """
        if peek:
            bites = self.__peek_stream(length)
        bites = self.stream.read(length)

        if length >= 0 and len(bites) != length:
            raise ValueError(
                f"Requested length mismatch: expected: {length} actual: {len(bites)}. Buffer overread?"
            )
        return bites

    def __simple_read(self, dml_type: DMLType, peek=False) -> Any:
        """Reads DMLTypes that are always the same size and
        can be unpacked using the python struct module.

        Args:
            dml_type (DMLType): The DMLType to read in
            peek (bool, optional): True if reading leaves the bytes in
              the buffer. Defaults to False.

        Raises:
            ValueError: if a known complex type is given (such as
                a length-prefixed string STR or WSTR)

        Returns:
            Any: the given DMLType's python representation
        """
        if dml_type in [DMLType.STR, DMLType.WSTR, DMLType.PO_STR, DMLType.PO_WSTR]:
            raise ValueError("Known special case. Cannot be read simply.")
        raw_bytes = self.read_raw(dml_type.length, peek=peek)[: dml_type.length]

        unpacked_repr = struct.unpack(dml_type.struct_code, raw_bytes)
        return unpacked_repr[0]

    # FIXME: Hack until https://github.com/python/cpython/pull/30808/files
    # is merged
    def __peek_stream(self, size=-1) -> bytes:
        pos = self.stream.tell()
        if size == 0:
            size = -1
        bites = self.stream.read(size)
        self.stream.seek(pos)
        return bites

    def __str_read(self, peek=False) -> str | bytes:
        buffer_pos = self.buffer_position()
        str_len = self.__simple_read(DMLType.USHRT, peek=peek)
        bites = self.stream.read(str_len)
        with contextlib.suppress(Exception):
            bites = bites.decode("ascii")
        if peek:
            self.stream.seek(buffer_pos)

        return bites

    # TODO: this is a weird scenario. Is it always text? Binary?
    def __wstr_read(self, peek=False):
        buffer_pos = self.buffer_position()
        str_len = self.__simple_read(DMLType.USHRT, peek=peek)
        bites = self.stream.read(str_len)
        try:
            return bites.decode("utf-16-le")
        except Exception:  # pylint: disable=broad-except
            return bites
        finally:
            if peek:
                self.stream.seek(buffer_pos)

    def advance(self, length: int):
        """Advance the internal stream by `length` bytes

        Args:
            length (int): number of bytes to advance
        """

        self.stream.read(length)

    def read(self, dml_type: DMLType, peek: bool = False) -> Any:
        """Reads a `DMLType` from the stream

        Args:
            dml_type (DMLType): Expected `DMLType` of the field
            peek (bool, optional): True if reading does not advance the reading head. Defaults to False.

        Returns:
            Any: decoded data based on the provided DMLType
        """

        if dml_type is DMLType.STR:
            return self.__str_read(peek)
        if dml_type is DMLType.WSTR:
            return self.__wstr_read(peek)
        return self.__simple_read(dml_type, peek)

    def peek(self, enc_type: DMLType) -> Any:
        """Reads a `DMLType` from the stream, not advancing the head.

        Args:
            enc_type (DMLType): Expected `DMLType` of the field

        Returns:
            Any: decoded data based on the provided DMLType
        """

        return self.read(enc_type, peek=True)

    def bytes_remaining(self) -> int:
        """Number of bytes remaining in the buffer

        Returns:
            int: num of bytes remaining in buffer
        """
        return self.stream.getbuffer().nbytes - self.stream.tell()

    def buffer_position(self) -> int:
        """Reading head's index in the buffer

        Returns:
            int: current index of reading head
        """
        return self.stream.tell()

    def get_buffer(self) -> memoryview:
        """Gets the reader's underlying buffer

        Under the hood, BytestreamReader is using `BytesIO` to scan over
        a message payload. `get_buffer` provides access to the underlying
        buffer of bytesio.

        Returns:
            memoryview: underlying buffer
        """
        return self.stream.getbuffer()

    def peek_remaining(self) -> bytes:
        """Get bytes remaining in the buffer

        Gets the remaining bytes in the buffer without advancing
        the reading head

        Returns:
            bytes: bytes remaining in the buffer
        """
        return bytes(self.get_buffer())[self.buffer_position() :]

    def __str__(self):
        return str(self.peek_remaining(), encoding="utf8")
        # return f"BytestreamReader(UINT8: {self.read(DMLType.UINT8, peek=True)}, UINT16: {self.read(DMLType.UINT16, peek=True)}, BYT: {hex(self.read(DMLType.BYT, peek=True))})"

    def __repr__(self) -> str:
        return self.__str__()
    
    @classmethod
    def from_bytes_or_passthrough(cls, bites: bytes | BytestreamReader) -> BytestreamReader:
        """
        from_bytes_or_passthrough takes a bytes object and makes a
            BytestreamReader from them or returns the original
            BytestreamReader as is if already one.

        Args:
            bites (bytes | BytestreamReader): bytes to wrap

        Returns:
            BytestreamReader: reader from given bytes or passthrough'd object
        """
        if type(bites) is bytes:
            return cls(bites)
        bites = cast(BytestreamReader, bites)
        return bites


@dataclass(repr=True, kw_only=True)
class KIHeader(SerdeMixin):
    """Dataclass holding the KI packet header fields."""

    food: bytes
    content_len: int
    content_is_control: int
    control_opcode: int
    mystery_bytes: bytes

    # def __init__(self, buffer: BytestreamReader | bytes) -> None:

    @classmethod
    def from_bytes(cls, bites: bytes | BytestreamReader) -> KIHeader:
        """Instantiates a new KIHeader from a packed bytestring

        Creates a new header object from the provided bytes,
        assuming they are valid

        Args:
            bites (bytes | BytestreamReader): packed Kingsisle TCP frame header

        Raises:
            ValueError: the provided bytes do not represent a KI tcp frame header

        Returns:
            KIHeader: unpacked KI network tcp header
        """

        if isinstance(bites, bytes):
            bites = BytestreamReader(bites)
        # validate content
        food = bites.read_raw(2)
        content_len = bites.read(DMLType.UINT16)
        content_is_control = bites.read(DMLType.UINT8)
        control_opcode = bites.read(DMLType.UINT8)
        mystery_bytes = bites.read(DMLType.UINT16)
        if food != b"\x0D\xF0":
            raise ValueError("Not a KI game protocol packet. F00D missing.")

        return cls(
            food=food,
            content_len=content_len,
            content_is_control=content_is_control,
            control_opcode=control_opcode,
            mystery_bytes=mystery_bytes,
        )
