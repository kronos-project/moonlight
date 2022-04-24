"""
    Shared stuff between the KI network protocol
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from email.header import Header
from enum import Enum
from collections import OrderedDict

import struct
from io import BytesIO
from types import LambdaType
from typing import Any, Tuple

PACKET_HEADER_LEN = 8
DML_HEADER_LEN = 2


class HumanReprMixin:
    """
    Mixin providing `as_human_dict`, a utility to translate an object into a
    human-friendly dict interpretation.

    HumanReprMixin is designed as to not need overriding of `as_human_dict`
    under most circumstances. Using the following class constants, the behavior
    and handling of desired object attributes can be changed.

    `HUMAN_REPR_IGNORE`: Tuple[str] of object attributes to never include in
    the resulting dictionary.

    `HUMAN_REPR_SYNTHETIC`: dict[str, LambdaType] of synthetic attributes to
    include in the resulting dictionary. Each lambda is called with `self` as
    an argument and inserts the result as is. Objects implementing
    `HumanReprMixin` will not automatically be converted and the lambda should
    call it explicitly.

    `HUMAN_REPR_COMPACT_IGNORE`: Tuple[str] of object attributes to exclude
    from the resulting dictionary if compact is set to `True`

    `HUMAN_REPR_RENAME`: dict[str, str] where attributes of the name `key`
    are instead included in the resulting dictionary with the name `value`.
    This does not apply to synthetic or static values.

    `HUMAN_REPR_REPR_ON_COMPACT`: bool where when `True` and `compact` mode
    is requested, the object's `__repr__` will be returned instead of the
    normal dictionary. Defaults to `False`.

    `HUMAN_REPR_ORDER_PREPEND`: Tuple[str] of resulting dictionary keys. If a given key
    is in the final dictionary, these keys will be first in the order given.
    Any keys not specified will be after these. Keys renamed via
    `HUMAN_REPR_RENAME` will need to be given with their new name,
    not the original.

    `HUMAN_REPR_ORDER_APPEND`: Tuple[str] of resulting dictionary keys. If a
    given key is in the final dictionary, these keys will always be last in the
    order given. Any keys not specified will be before these. Keys renamed via
    `HUMAN_REPR_RENAME` will need to be given with their new name, not the
    original.

    Example:
           @dataclass(init=True)
           class ADataclass(HumanReprMixin):
               HUMAN_REPR_IGNORE = ("ignore_me")
               HUMAN_REPR_COMPACT_IGNORE = ("sometimes_ignore_me")
               HUMAN_REPR_RENAME = {"an_abv": "annoying_abbreviation"}
               HUMAN_REPR_ORDER_PREPEND = ("me_first", "me_second")
               HUMAN_REPR_ORDER_APPEND = ("me_last")
               HUMAN_REPR_SYNTHETIC = {"im_not_real": lambda x: x.__name__}

               ignore_me: bool
               include_me: bool
               sometimes_ignore_me: bool
               me_first: bool
               me_second: bool
               me_last: bool
               an_abv: str

           >> obj.as_human_dict(compact=False)
           {
               "me_first": True,
               "me_second": True,
               "include_me": True,
               "im_not_real": "ADataclass",
               "annoying_abbreviation": "WYSIWYG",
               "me_last"
           }
    """

    HUMAN_REPR_IGNORE: Tuple[str] = ()
    HUMAN_REPR_SYNTHETIC: dict[str, LambdaType] = {}
    HUMAN_REPR_STATIC: dict[str, Any] = {}
    HUMAN_REPR_COMPACT_IGNORE: Tuple[str] = ()
    HUMAN_REPR_RENAME: dict[str, str] = {}
    HUMAN_REPR_REPR_ON_COMPACT: bool = False
    HUMAN_REPR_ORDER_PREPEND: Tuple[str] = ()
    HUMAN_REPR_ORDER_APPEND: Tuple[str] = ()

    def as_human_dict(self, compact=True) -> dict[str, Any] | str:
        keypairs: dict[str, Any] = {}

        if self.HUMAN_REPR_REPR_ON_COMPACT:
            return repr(self)

        for key, val in vars(self).items():
            if key in self.HUMAN_REPR_IGNORE:
                continue
            if compact and key in self.HUMAN_REPR_COMPACT_IGNORE:
                continue

            # turn any HRM attribute into its dict first
            if isinstance(val, HumanReprMixin):
                # replace output name if requested
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = val.as_human_dict(
                    compact=compact
                )
            # convert any HRM objects within list or dict attributes
            elif isinstance(val, list):
                tmp = []
                for subitem in val:
                    if isinstance(subitem, HumanReprMixin):
                        tmp.append(subitem.as_human_dict(compact=compact))
                    else:
                        tmp.append(subitem)
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = tmp
            elif isinstance(val, dict):
                tmp = {}
                for subkey, subvalue in val.items():
                    if isinstance(subvalue, HumanReprMixin):
                        tmp[subkey] = subvalue.as_human_dict(compact=compact)
                    else:
                        tmp[subkey] = subvalue
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = tmp
            else:
                # anything else is left to the whims of what's outputting the end dict
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = val

        for key, val in self.HUMAN_REPR_SYNTHETIC.items():
            try:
                if compact and key in self.HUMAN_REPR_COMPACT_IGNORE:
                    continue
                tmp = val(self)
                keypairs[key] = val(self)
            # we don't want synthetics in an invalid state to cause a crash
            # attribute and value errors are possible here
            except Exception as err:  # pylint: disable=broad-except
                keypairs[key] = f"Failed: {err}"

        for key, val in self.HUMAN_REPR_STATIC:
            keypairs[key] = val

        # no need to do reordering if not requested
        if not self.HUMAN_REPR_ORDER_PREPEND and not self.HUMAN_REPR_ORDER_APPEND:
            return keypairs

        keypairs_sorted: dict[str, Any] = {}
        for ordered_key in self.HUMAN_REPR_ORDER_PREPEND:
            if ordered_key in keypairs:
                keypairs_sorted[ordered_key] = keypairs[ordered_key]

        # include unordered keys
        # the order they're defined controls most printing systems
        for key, value in keypairs.items():
            if key not in self.HUMAN_REPR_ORDER_APPEND:
                keypairs_sorted[key] = value

        # and finally ordered to append
        for key, value in keypairs.items():
            if key in self.HUMAN_REPR_ORDER_APPEND:
                keypairs_sorted[key] = value

        return keypairs_sorted


class MessageSender(HumanReprMixin, Enum):
    CLIENT = 1
    SERVER = 2
    FLAGTOOL = 3

    def __init__(self, sender) -> None:
        self.netpack_port = sender

    # override since we cant use the class constants to customize
    def as_human_dict(self, compact=True) -> dict[str, Any] | str:
        return self.name

    @classmethod
    def from_capture_port(cls, port: int) -> MessageSender | None:
        for const in cls:
            if const.netpack_port == port:
                return const
        return None


@dataclass(init=True, repr=True, kw_only=True)
class Message(HumanReprMixin):
    original_bytes: bytes
    packet_header: Header = None
    sender: MessageSender | None = None
    timestamp: datetime | None = None

    HUMAN_REPR_ORDER_PREPEND = ("timestamp", "sender")
    HUMAN_REPR_ORDER_APPEND = ("packet_header", "original_bytes")


class DMLType(HumanReprMixin, Enum):
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

    def as_human_dict(self, compact=True):
        return repr(self)

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
            bites = self.__peek_stream(length)
        bites = self.stream.read(length)

        if length >= 0 and len(bites) != length:
            raise ValueError(
                f"Requested length mismatch: expected: {length} actual: {len(bites)}. Buffer overread?"
            )
        return bites

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
        raw_bytes = self.read_raw(dml_type.length, peek=peek)[: dml_type.length]

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

    def __str_read(self, peek=False):
        buffer_pos = self.buffer_position()
        str_len = self.__simple_read(DMLType.USHRT, peek=peek)
        bites = self.stream.read(str_len)
        try:
            bites = bites.decode("ascii")
        except Exception:  # pylint: disable=broad-except
            pass

        if peek:
            self.stream.seek(buffer_pos)

        return bites

    # TODO: this is a weird scenario. Is it always text? Binary?
    def __wstr_read(self, peek=False):
        buffer_pos = self.buffer_position()
        str_len = self.__simple_read(DMLType.USHRT, peek=peek)
        bites = self.stream.read(str_len)
        try:
            return bytes.decode("utf-16-le")
        except Exception:  # pylint: disable=broad-except
            return bites
        finally:
            if peek:
                self.stream.seek(buffer_pos)

    def advance(self, length: int):
        """advance advances the internal stream by `length` bytes

        Args:
            length (int): number of bytes to advance
        """

        self.stream.read(length)

    def read(self, dml_type: DMLType, peek: bool = False):
        """read reads a `DMLType` from the stream

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
        """peek reads a `DMLType` from the stream, not advancing the head.

        Args:
            enc_type (DMLType): Expected `DMLType` of the field

        Returns:
            _type_: _description_
        """

        return self.read(enc_type, peek=True)

    def bytes_remaining(self):
        return self.stream.getbuffer().nbytes - self.stream.tell()

    def buffer_position(self):
        return self.stream.tell()

    def get_buffer(self):
        return self.stream.getbuffer()

    def __str__(self):
        return f"BytestreamReader(UINT8: {self.read(DMLType.UINT8, peek=True)}, UINT16: {self.read(DMLType.UINT16, peek=True)}, BYT: {hex(self.read(DMLType.BYT, peek=True))})"

    def __repr__(self) -> str:
        return self.__str__()


class PacketHeader(HumanReprMixin):
    """Dataclass holding the KI packet header fields.

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
        return repr(self)

    def as_human_dict(self, compact=True) -> dict[str, Any] | str:
        return repr(self)

    def __repr__(self) -> str:
        return f"<PacketHeader content_len={self.content_len} content_is_control={hex(self.content_is_control)} control_opcode={hex(self.control_opcode)}>"
