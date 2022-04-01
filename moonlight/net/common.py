"""
    Shared stuff between the KI network protocol
"""

from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass

import struct
from enum import Enum
from io import BytesIO
from typing import Any, Union

PACKET_HEADER_LEN = 8
DML_HEADER_LEN = 2


class DMLType(Enum):
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
    INT8 = ("int8", 1, "<b")
    UINT8 = ("uint8", 1, "<B")
    INT16 = ("int16", 2, "<h")
    UINT16 = ("uint16", 2, "<H")
    INT32 = ("int32", 4, "<i")
    UINT32 = ("uint32", 4, "<I")
    FLOAT32 = ("float32", 4, "<f")
    FLOAT64 = ("float64", 8, "<d")
    UINT64 = ("uint64", 8, "<q")
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
        self.t_name = t_name
        self.length = length
        self.struct_code = struct_code

    @classmethod
    def from_str(cls, t_name: str) -> DMLType | None:  # sourcery skip: use-next
        """
        from_str enum described by the given string or `None` if invalid

        Args:
            t_name (str): The enum's name.

        Returns:
            DMLType | None: enum described by the given string or `None` if invalid
        """
        for enum in cls:
            if enum.t_name == t_name:
                return enum
        return None

    def __str__(self):
        return self.t_name

    def __repr__(self) -> str:
        return f"<DMLType.{self.t_name}>"


class BytestreamReader:
    """Wrapper of BufferedReader used to simplify reading bytestrings
    into their standard type value. Accepts any DMLType not prefaced
    with a length. Otherwise, you'll need to modify this as a special
    case.
    """

    def __init__(self, bites: bytes) -> None:
        """Initializes a BytestreamReader with a bytestring

        Args:
            bites ([bytes]): [bytestring to read]
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
            return self.__peek_stream(length)
        return self.stream.read(length)

    def at_packet_terminate(self):
        return self.bytes_remaining() == 1 and self.read_raw(1) == b"\x00"

    def __simple_read(self, dml_type: DMLType, peek=False) -> Any:
        """
        __simple_read reads DMLTypes that are always the same size and
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
        raw_bytes = None
        if peek:
            raw_bytes = self.__peek_stream(dml_type.length)[: dml_type.length]
        else:
            raw_bytes = self.stream.read(dml_type.length)

        unpacked_repr = struct.unpack(dml_type.struct_code, raw_bytes)
        return unpacked_repr[0]

    # FIXME: Hack until https://github.com/python/cpython/pull/30808/files
    # is merged
    def __peek_stream(self, size=-1):
        pos = self.stream.tell()
        if size == 0:
            size = -1
        b = self.stream.read(size)
        self.stream.seek(pos)
        return b

    # FIXME peek doesn't work on strings
    # FIXME refactor to just return bytes. Most things dont use strings
    def __str_read(self, peek=False, decode: bool = True):
        str_len = self.__simple_read(DMLType.USHRT, peek=peek)
        if str_len > 0:
            bites = self.stream.read(str_len)
        else:
            bites = b""

        if not decode:
            return bites
        try:
            return bytes.decode("utf-8")
        except:  # pylint: disable=bare-except
            return bites

    # TODO: this is a weird scenario. Is it always text? Binary?
    def __wstr_read(self, peek=False):
        str_len = self.__simple_read(DMLType.USHRT, peek=peek)
        bites = self.stream.read(str_len)
        try:
            return bytes.decode("utf-16-le")
        except:  # pylint: disable=bare-except
            return bites

    def advance(self, length: int):
        """
        advance advances the internal stream by `length` bytes

        Args:
            length (int): number of bytes to advance
        """

        self.stream.read(length)

    def read(self, dml_type: DMLType, peek: bool = False):
        """
        read reads a `DMLType` from the stream

        Args:
            dml_type (DMLType): Expected `DMLType` of the field
            peek (bool, optional): True if reading does not advance the reading head. Defaults to False.

        Returns:
            _type_: _description_
        """

        if dml_type is DMLType.STR:
            return self.__str_read(peek)
        if dml_type is DMLType.WSTR:
            return self.__wstr_read(peek)
        return self.__simple_read(dml_type, peek)

    def peek(self, enc_type: DMLType):
        """
        peek reads a `DMLType` from the stream, not advancing the head.

        Args:
            enc_type (DMLType): Expected `DMLType` of the field

        Returns:
            _type_: _description_
        """

        return self.read(enc_type, peek=True)

    def bytes_remaining(self):
        return self.stream.getbuffer().nbytes - self.stream.tell()

    def __str__(self):
        return f"BytestreamReader(UINT8: {self.read(DMLType.UINT8, peek=True)}, UINT16: {self.read(DMLType.UINT16, peek=True)}, BYT: {hex(self.read(DMLType.BYT, peek=True))})"

    def __repr__(self) -> str:
        return self.__str__()


# @dataclass
# class BaseMessage:
#     """
#     Dataclass intended to create an interface for different messages and
#     so that all bytes can be held onto.
#     """

#     def __init__(
#         self, protocol_class: "MessageProtocol", original_bytes: bytes = None
#     ) -> None:
#         """
#         __init__

#         Args:
#             protocol_class (MessageProtocol): protocol of the message
#             original_bytes (bytes, optional): original bytes of the message. Defaults to None.
#         """
#         self.protocol_class = protocol_class
#         self.original_bytes = original_bytes


class PacketHeader:
    """
    Dataclass holding the KI packet header fields.

    Note: Passing in a BytestreamReader instead of bytes will change the current
    position of the reader.
    """

    def __init__(self, buffer: BytestreamReader | bytes) -> None:
        if isinstance(buffer, bytes):
            buffer = BytestreamReader(buffer)
        # validate content
        food = buffer.read(DMLType.UINT16)
        self.content_len = buffer.read(DMLType.UINT16)
        self.content_is_control = buffer.read(DMLType.UINT8)
        self.control_opcode = buffer.read(DMLType.UINT8)
        self.mystery_bytes = buffer.read(DMLType.UINT16)
        if food != 0xF00D:
            raise ValueError("Not a KI game protocol packet. F00D missing.")

    def to_human_dict(self):
        return vars(self)

    def __repr__(self) -> str:
        return f"<PacketHeader content_len={self.content_len} content_is_control={hex(self.content_is_control)} control_opcode={hex(self.control_opcode)}>"
