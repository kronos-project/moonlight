"""
    Shared stuff between the KI network protocol
"""

from enum import Enum
from io import BufferedReader
import io
import logging
from os import PathLike, read
import struct
from typing import Any, ByteString, List, NewType, Optional, Union
from printrospector import BinarySerializer, TypeCache
from .object_property import build_property_object_serde

KI_HEADER_LEN = 8
DML_HEADER_LEN = 2


class EncodingType(Enum):
    """Bit encodings used by the KI network protocol.

    Args:
        t_name (str): Name used in encodings. Same as the enum names.
        len (int): Number of bytes used in the initial read for the field.
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
    STR = (
        "STR",
        2,
        "<H",
    )  # uint16 length definition followed by utf8
    OBJSTR = (
        "OBJSTR",
        2,
        "<H",
    )  # uint16 length definition followed by utf8 encoding a PropertyObject
    WSTR = ("WSTR", 2, "<H")  # uint16 length definition followed by utf16 LE
    OBJWSTR = ("OBJWSTR", 2, "<H")  # uint16 length definition followed by utf16 LE encoding a PropertyObject
    FLT = ("FLT", 4, "<f")  # float32
    DBL = ("DBL", 8, "<d")  # float64
    GID = ("GID", 8, "<q")  # uint64

    def __init__(self, t_name, len, struct_code):
        self.t_name = t_name
        self.len = len
        self.struct_code = struct_code

    def from_str(name):
        for type in EncodingType:
            if type.t_name == name:
                return type

    def __str__(self):
        return self.t_name

    def __repr__(self) -> str:
        return f"<EncodingType.{self.t_name}>"


class BytestreamReader:
    """Wrapper of BufferedReader used to simplify reading bytestrings
    into their standard type value. Accepts any EncodingType not prefaced
    with a length. Otherwise, you'll need to modify this as a special
    case.
    """

    object_property_serde = None

    def __init__(self, bites: bytes, type_file: PathLike = None) -> None:
        """Initializes a BytestreamReader with a bytestring

        Args:
            bites ([bytes]): [bytestring to read]
        """
        self.stream = BufferedReader(io.BytesIO(bites))
        if not BytestreamReader.object_property_serde and type_file:
            BytestreamReader.object_property_serde = build_property_object_serde(type_file)



    def read_raw(self, len: int, peek=False) -> bytes:
        """Reads the given number of bytes off the string, peeking+truncate
        if requested

        Args:
            len (int): number of bytes to read
            peek (bool, optional): True if reading leaves the bytes in
              the buffer. Defaults to False.
        """
        if peek:
            return self.stream.peek(len)
        else:
            return self.stream.read(len)

    def __simple_read(self, enc_type: EncodingType, peek=False) -> Any:
        """
        __simple_read reads EncodingTypes that are always the same size and
        can be unpacked using the python struct module.

        Args:
            enc_type (EncodingType): The EncodingType to read in
            peek (bool, optional): True if reading leaves the bytes in
              the buffer. Defaults to False.

        Raises:
            ValueError: if a known complex type is given (such as
              a length-prefixed string STR or WSTR)

        Returns:
            Any: the given EncodingType's python representation
        """
        if enc_type in [EncodingType.STR, EncodingType.WSTR, EncodingType.OBJSTR, EncodingType.WSTR]:
            raise ValueError("Known special case. Cannot be read simply.")
        raw_bytes = None
        if peek:
            raw_bytes = self.stream.peek(enc_type.len)[: enc_type.len]
        else:
            raw_bytes = self.stream.read(enc_type.len)

        unpacked_repr = struct.unpack(enc_type.struct_code, raw_bytes)
        return unpacked_repr[0]

    # FIXME peek doesn't work on strings
    def __str_read(self, peek=False, decode: bool = True):
        str_len = self.__simple_read(EncodingType.USHRT, peek=peek)
        bytes = self.stream.read(str_len)
        if not decode:
            return bytes
        try:
            return bytes.decode("utf-8")
        except:
            return bytes

    def __property_object_str_read(self, peek=False):
        bytes = self.__str_read(peek=peek, decode=False)
        if BytestreamReader.object_property_serde:
            return BytestreamReader.object_property_serde.deserialize(bytes)
        return bytes

    
    def __property_object_wstr_read(self, peek=False):
        bytes = self.__wstr_read(peek=peek, decode=False)
        if BytestreamReader.object_property_serde:
            return BytestreamReader.object_property_serde.deserialize(bytes)
        return bytes
        


    def __wstr_read(self, peek=False):
        str_len = self.__simple_read(EncodingType.USHRT, peek=peek)
        bytes = self.stream.read(str_len)
        try:
            return bytes.decode("utf-16-le")
        except:
            return bytes

    def advance(self, num_of_bytes):
        self.stream.read(num_of_bytes)

    def read(self, enc_type, peek=False):
        if enc_type is EncodingType.STR:
            return self.__str_read(peek)
        elif enc_type is EncodingType.OBJSTR:
            return 
        elif enc_type is EncodingType.WSTR:
            return self.__wstr_read(peek)
        else:
            return self.__simple_read(enc_type, peek)

    def peek(self, enc_type):
        return self.read(enc_type, peek=True)

    def __str__(self):
        return f"BytestreamReader(UINT8: {self.read(EncodingType.UINT8, peek=True)}, UINT16: {self.read(EncodingType.UINT16, peek=True)}, BYT: {hex(self.read(EncodingType.BYT, peek=True))})"

    def __repr__(self) -> str:
        return self.__str__()


class KIMessage:
    def __init__(self, protocol_class, original_bytes: ByteString = None) -> None:
        self.protocol_class = protocol_class
        self.original_bytes = original_bytes


class KIPacketHeader:
    def __init__(self, reader: BytestreamReader) -> None:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        # validate content
        food = reader.read(EncodingType.UINT16)
        self.content_len = reader.read(EncodingType.UINT16)
        self.content_is_control = reader.read(EncodingType.UINT8)
        self.control_opcode = reader.read(EncodingType.UINT8)
        self.mystery_bytes = reader.read(EncodingType.UINT16)
        if food != 0xF00D:
            raise ValueError("Not a KI game protocol packet. F00D missing.")


class KIMessageDecoder:
    """
    Notice: this is an abstract class and must be implemented by another.

    A generic decoder capable of decoding a specific message in the KI protocol.
    Decoders should be able to return the represented object without access to additional context beyond the provided bytes.

    For example, DML message decoders provided all bytes following the KI header should be able to determine the correct service and message ID.
    However, control messages rely on the content of the header. Therefore, they have a decoder per message due to the different parsing rules based on that header.

    Raises:
        NotImplementedError: This is an abstract class
    """

    def __init__(self) -> None:
        pass

    def decode_message(
        self, reader: Union[BytestreamReader, bytes], **kwargs
    ) -> KIMessage:
        """
        decode_message Decodes a KI message (missing protocol context)

        Args:
            reader (BytestreamReader | bytes): data to parse

        Raises:
            NotImplementedError: This is an abstract class

        Returns:
            KIMessage: essage the provided packet decodes to
        """
        raise NotImplementedError()


class KIMessageProtocol:
    """
    Notice: this is an abstract class and must be implemented by another.

    A generic protocol
    """

    def __init__(self) -> None:
        pass

    def decode_packet(
        self,
        reader: Union[BytestreamReader, bytes],
        header: KIPacketHeader,
        original_data: bytes = None,
        **kwargs,
    ) -> KIMessage:
        """
        decode_packet Decodes a KI packet from the implementing protocol
        returning a KI message implementation

        Args:
            reader (BytestreamReader | bytes): data to parse
            header (KIPacketHeader): packet's header frame
            original_data (bytes, optional): Original bytes. Defaults to None and is optional.

        Raises:
            NotImplementedError: This is an abstract class

        Returns:
            KIMessage: message the provided packet decodes to
        """
        raise NotImplementedError()
