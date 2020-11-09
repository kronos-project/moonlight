from collections import namedtuple
from enum import Enum
from io import BufferedReader
import io
import logging
from os import read
import struct
from typing import Any, List, NewType


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
    BYT = ("BYT", 1, "<b")  # uint8
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
    WSTR = ("WSTR", 2, "<H")  # uint16 length definition followed by utf16 LE
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
    def __init__(self, bites: bytes) -> None:
        """Initializes a BytestreamReader with a bytestring

        Args:
            bites ([bytes]): [bytestring to read]
        """
        self.stream = BufferedReader(io.BytesIO(bites))

    def __read(self, len: int, peek=False) -> bytes:
        """Reads the given number of bytes off the string, peeking+truncate
        if requested

        Args:
            len (int): number of bytes to read
            peek (bool, optional): True if reading leaves the bytes in
              the buffer. Defaults to False.
        """
        if peek:
            self.stream.peek(len)
        else:
            self.stream.read(len)

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
        if enc_type is EncodingType.STR or enc_type is EncodingType.WSTR:
            raise ValueError("Known special case. Cannot be read simply.")
        raw_bytes = None
        if peek:
            raw_bytes = self.stream.peek(enc_type.len)[0 : enc_type.len]
        else:
            raw_bytes = self.stream.read(enc_type.len)

        unpacked_repr = struct.unpack(enc_type.struct_code, raw_bytes)
        return unpacked_repr[0]

    # FIXME peek doesn't work on strings
    def __str_read(self, peek=False):
        str_len = self.__simple_read(EncodingType.USHRT, peek=peek)
        bytes = self.stream.read(str_len)
        try:
            return bytes.decode("utf-8")
        except:
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
        elif enc_type is EncodingType.WSTR:
            return self.__wstr_read(peek)
        else:
            return self.__simple_read(enc_type, peek)

    def peek(self, enc_type):
        return self.read(enc_type, peek=True)


class DMLMessageObject:
    def __init__(
        self,
        fields: List,
        protocol_id: int = -1,
        protocol_desc: str = None,
        msg_id: int = -1,
        msg_desc: str = None,
        source: str = None,
    ):
        self.fields = fields
        self.protocol_id = protocol_id
        self.protocol_desc = protocol_desc
        self.msg_id = msg_id
        self.msg_desc = msg_desc
        self.source = source

    def __repr__(self) -> str:
        return (
            f"DMLMessageObject:\n"
            f"  source = {self.source}\n"
            f"  protocol_id = {self.protocol_id}\n"
            f"  msg_id = {self.msg_id}\n"
            f"  protocol_desc = {self.protocol_desc}\n"
            f"  msg_desc = {self.msg_desc}\n"
            f"  fields = {self.fields}"
        )


class DMLMessageDef:
    """Defines a DML interface message and its structure"""

    def __init__(self, fields):
        """Initializes a DML message definition from an XML record

        Args:
            fields (Element): "Record" XML Element to load
        """
        self.id = None
        self.name = None
        self.desc = None
        self.handler = None
        self.fields = []
        for field in list(fields):
            if field.tag == "_MsgName":
                self.name = field.text
            elif field.tag == "_MsgDescription":
                self.desc = field.text
            elif field.tag == "_MsgHandler":
                self.handler = field.text
            else:
                field_map = {}
                field_map["name"] = field.tag
                field_map["text"] = (field.text or "").strip()
                field_map["type"] = EncodingType.from_str(field.attrib.get("TYPE"))
                field_map["noxfer"] = field.attrib.get("NOXFER") == "TRUE"
                self.fields.append(field_map)

    def get(self, name: str) -> map:
        """Finds and returns the field matching the given name

        Args:
            name (str): name of the field to retreive

        Returns:
            map: attributes in the field DML definition
        """
        for field in self.fields:
            if field["name"] == name:
                return field.copy()
        return None

    def decode_message(
        self,
        reader: BytestreamReader,
        no_ki_header=True,
        no_msg_header=True,
        no_dml_header=True,
    ):
        if not no_ki_header:
            # advance past ki header and message header
            reader.advance(12)
        elif not no_msg_header:
            # advance past message header
            reader.advance(8)
        elif not no_dml_header:
            reader.advance(4)

        decoded_fields = []
        for field in self.fields:
            DMLField = namedtuple(field["name"], ["name", "value", "src_encoding"])
            value = reader.read(field["type"])
            decoded_fields.append(DMLField(field["name"], value, field["type"]))

        return DMLMessageObject(decoded_fields, msg_id=self.id, msg_desc=self.desc)

    def __str__(self) -> str:
        return f"{self.id}: {self.name}"

    def __repr__(self) -> str:
        return f"""DMLMessageDef:
            id = {self.id}
            name = {self.name}
            desc = {self.desc}
            handler = {self.handler}
            fields = {self.fields}"""

    @staticmethod
    def list_to_id_map(defs) -> map:
        """Sorts a list of messages, assigns ids, and returns the mapping

        Args:
            list ([DMLMessageDef]): list of DMLMessageDefs to sort and assign ids
        """
        # sort on the definition name
        def msg_key(msg):
            return msg.name

        # sort and assign ids based on ordinal (ASCII chart) order
        defs.sort(key=msg_key)

        # assign ids
        id_map = {}
        for i, dml_def in enumerate(defs, start=1):
            dml_def.id = i
            id_map[i] = dml_def

        return id_map


class DMLProtocol:
    def parse_dml_file(self, filename: str) -> None:
        """Loads the protocol according to the given xml

        Args:
            filename (str): [description]
        """
        import xml.etree.ElementTree as ET

        tree = ET.parse(filename)
        root = tree.getroot()
        message_blocks = []

        # store protocol block as our own instance vars, not as a block
        for block in list(root):
            record = list(block)[0]
            dml_def = DMLMessageDef(record)
            if block.tag == "_ProtocolInfo":
                self.service_id = int(dml_def.get("ServiceID")["text"])
                self.type = dml_def.get("ProtocolType")["text"]
                self.version = int(dml_def.get("ProtocolVersion")["text"])
                self.description = dml_def.get("ProtocolDescription")["text"]
            else:
                message_blocks.append(dml_def)

        # sort the message blocks and assign their record id
        self.message_map = DMLMessageDef.list_to_id_map(message_blocks)

    def __init__(self, filename="") -> None:
        self.service_id = None
        self.type = None
        self.version = None
        self.description = None
        self.message_map = {}

        if len(filename) > 0:
            self.parse_dml_file(filename)

    def decode_message(
        self,
        reader: BytestreamReader,
        no_ki_header=True,
        no_msg_header=True,
        no_service_id=False,
    ):
        if not no_ki_header:
            # advance past ki and msg header
            reader.advance(8)
        elif not no_msg_header:
            # advance past msg header
            reader.advance(4)

        # read dml header information
        if not no_service_id:
            service_id = reader.read(EncodingType.UBYT)
            if service_id != self.service_id:
                raise Exception("Invalid protocol for this message")

        message_id = reader.read(EncodingType.UBYT)
        len = reader.read(EncodingType.USHRT)

        dml_object = self.message_map[message_id].decode_message(reader)
        if dml_object != None:
            dml_object.protocol_id = self.service_id
            dml_object.protocol_desc = self.description
        return dml_object


class WizDMLDecoder:
    def load_protocol(self, protocol_file):
        protocol = DMLProtocol(protocol_file)
        logging.info(f"loaded protocol {protocol.service_id}: {protocol.description}")
        self.protocol_map[protocol.service_id] = protocol

    def __init__(self, *args) -> None:
        self.protocol_map = {}
        if args != None and len(args) > 0:
            for f in args:
                self.load_protocol(f)

    def decode_message(
        self, data: bytes, no_ki_header=False, no_msg_header=False
    ) -> DMLMessageObject:
        reader = BytestreamReader(data)
        food = None
        len = None
        is_control = None
        opcode = None
        mystery_bytes = None

        if not no_ki_header:
            # validate content
            food = reader.read(EncodingType.UINT16)
            len = reader.read(EncodingType.UINT16)

            if food != 0xF00D:
                logging.info("Not a KI protocol packet. Probably patch data.")
                return None
        if not no_msg_header:
            # advance past msg header
            is_control = reader.read(EncodingType.UINT8)
            opcode = reader.read(EncodingType.UINT8)
            mystery_bytes = reader.read(EncodingType.UINT16)

            if is_control != 0:
                logging.debug("is a control message")
                return None
            if opcode != 0:
                logging.warn("umm. it says not a control, but I got control data. wat.")
                return None

        service_id = reader.peek(EncodingType.UBYT)
        if service_id not in self.protocol_map:
            logging.warn(f"unknown protocol: {service_id}")
            return None  # implement custom exception
        return self.protocol_map[service_id].decode_message(reader)


if __name__ == "__main__":
    from os import listdir
    from os.path import isfile, join

    res_folder = "/Users/ethanzeigler/Programming/offshot projects/KI/moonlight/res/dml/messages/"
    protocols = [f for f in listdir(res_folder) if isfile(join(res_folder, f))]
    protocols = map(lambda x: join(res_folder, x), protocols)
    decoder = WizDMLDecoder(*protocols)

    for f in ["packet.bin", "packet2.bin", "packet3.bin", "packet4.bin"]:
        bin = open(f"/Users/ethanzeigler/Desktop/{f}", "rb").read()
        print(f"decoded data: {decoder.decode_message(bin)}")
    print("bye")
