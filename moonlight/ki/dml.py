from collections import namedtuple
from overrides import overrides
import logging
from typing import Dict, List, Union
from .net_common import (
    DML_HEADER_LEN,
    KI_HEADER_LEN,
    BytestreamReader,
    EncodingType,
    KIMessage,
    KIMessageDecoder,
    KIPacketHeader,
    KIMessageProtocol,
)

SERVICE_ID_SIZE = 1
MESSAGE_ID_SIZE = 1


class DMLMessageObject(KIMessage):
    def __init__(
        self,
        fields: List,
        protocol_id: int = None,
        protocol_desc: str = None,
        msg_id: int = None,
        order_id: int = None,
        msg_desc: str = None,
        source: str = None,
    ):
        super(DMLService)
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


class DMLMessageDecoder(KIMessageDecoder):
    """Defines a DML interface message and its structure.
    Provides a deserializer for the represented message."""

    def __init__(self, fields):
        """Initializes a DML message definition from an XML record

        Args:
            fields (Element): "Record" XML Element to load
        """
        self.id = None
        self.order = None
        self.name = None
        self.desc = None
        self.handler = None
        self.fields = []
        for field in list(fields):
            if field.tag == "_MsgDescription":
                self.desc = field.text
            elif field.tag == "_MsgHandler":
                self.handler = field.text
            elif field.tag == "_MsgName":
                self.name = field.text
            elif field.tag == "_MsgOrder":
                self.order = int(field.text)
            else:
                field_map = {"name": field.tag, "text": (field.text or "").strip()}
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
        reader: Union[BytestreamReader, bytes],
        has_ki_header=False,
        has_dml_header=False,
        **kwargs,
    ) -> DMLMessageObject:
        if has_ki_header:
            # advance past ki header and message header
            reader.advance(KI_HEADER_LEN)
        elif has_dml_header:
            reader.advance(DML_HEADER_LEN)

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
            order = {self.order}
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
        # sort on the order number, or definition name if undefined
        # FIXME: is there a case where both are given?
        def msg_key(msg):
            if msg.order is None:
                return msg.name
            else:
                return msg.order

        # sort and assign ids based on ordinal (ASCII chart) order
        defs.sort(key=msg_key)

        # assign ids
        id_map = {}
        for i, dml_def in enumerate(defs, start=1):
            if dml_def.order != None and i != dml_def.order:
                raise Exception("Bad order to id conversion caught")
            dml_def.id = i

            id_map[i] = dml_def

        return id_map


class DMLService:
    def parse_dml_file(self, filename: str) -> None:
        """Loads the protocol according to the given xml

        Args:
            filename (str): [Protocol to load]
        """
        import xml.etree.ElementTree as ET

        tree = ET.parse(filename)
        root = tree.getroot()
        message_blocks = []

        # store protocol block as our own instance vars, not as a block
        for block in list(root):
            record = list(block)[0]
            dml_def = DMLMessageDecoder(record)
            if block.tag == "_ProtocolInfo":
                self.id = int(dml_def.get("ServiceID")["text"])
                self.type = dml_def.get("ProtocolType")["text"]
                self.version = int(dml_def.get("ProtocolVersion")["text"])
                self.description = dml_def.get("ProtocolDescription")["text"]
            else:
                message_blocks.append(dml_def)

        # sort the message blocks and assign their record id
        self.message_map = DMLMessageDecoder.list_to_id_map(message_blocks)

    def __init__(self, filename="") -> None:
        self.id = None
        self.type = None
        self.version = None
        self.description = None
        self.message_map = {}
        if len(filename) > 0:
            self.parse_dml_file(filename)

    def decode_dml_service(
        self,
        reader: BytestreamReader,
        original_data: bytes = None,
        has_service_id=False,
    ):
        """
        decode_packet Decodes a packet from the represented DML service.
          Reads provided data starting from the message ID unless `has_service_id` is set

        Args:
            reader (BytestreamReader): [description]
            header (KIPacketHeader): [description]
            original_data (bytes, optional): [description]. Defaults to None.
            has_service_id (bool, optional): [description]. Defaults to False.

        Raises:
            Exception: [description]

        Returns:
            [type]: [description]
        """
        # sanity check
        if has_service_id:
            service_id = reader.read(EncodingType.UBYT)
            if service_id != self.id:
                raise Exception("Invalid protocol for this message")

        message_id: int = reader.read(EncodingType.UBYT)
        len: int = reader.read(EncodingType.USHRT)
        try:
            dml_object: DMLMessageObject = self.message_map[message_id].decode_message(
                reader
            )
        except:
            logging.error(
                "Failed to decode message. "
                f"protocol_id: {self.id}, "
                f"msg_id: {self.message_map[message_id]}, "
                f"packet_data (optional): [{original_data}]"
            )
            return None
        if dml_object != None:
            dml_object.protocol_id = self.id
            dml_object.protocol_desc = self.description
        return dml_object


class DMLProtocol(KIMessageProtocol):
    def load_service(self, protocol_file):
        service = DMLService(protocol_file)
        logging.info(f"loaded protocol {service.id}: {service.description}")
        for msg in service.message_map.values():
            logging.debug(f"\t{repr(msg)}")
        self.protocol_map[service.id] = service

    def __init__(self, *service_files) -> None:
        self.protocol_map: Dict[int, DMLProtocol] = {}
        if service_files is None or len(service_files) < 1:
            return

        for f in service_files:
            self.load_service(f)

    def decode_packet(
        self,
        reader: Union[BytestreamReader, bytes],
        has_ki_header: bool = False,
    ) -> DMLMessageObject:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(KI_HEADER_LEN)
        service_id = reader.peek(EncodingType.UBYT)
        if service_id not in self.protocol_map:
            logging.warn(f"unknown dml protocol: {service_id}")
            return None  # implement custom exception
        return self.protocol_map[service_id].decode_dml_service(
            reader, has_service_id=True
        )
