"""
Parser for DML message definitions and parsing messages based on them
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree
from collections import namedtuple
from os import PathLike
from typing import Any, Dict, List, Union

from printrospector.object import DynamicObject
from printrospector.type_cache import TypeCache

from moonlight.ki.net_common import (
    DML_HEADER_LEN,
    PACKET_HEADER_LEN,
    BaseMessage,
    BaseMessageDecoder,
    BytestreamReader,
    DMLType,
    MessageProtocol,
)

from .object_property import ObjectPropertyDecoder

SERVICE_ID_SIZE = 1
MESSAGE_ID_SIZE = 1


class FieldDef:
    """
    Definition of a DML field within a message. Used to hold the represented
    xml from message definition files as well as property object decoding
    information.
    """

    # FIXME reduce number of fields. It's okay for now since this isn't
    # part of the public api.
    def __init__(  # pylint: disable=too-many-arguments
        self,
        name: str,
        text: str,
        dml_type: DMLType,
        property_object_flags: int | None = None,
        property_object_mask: int | None = None,
        property_object_exhaustive: bool | None = None,
        noxfer: bool | None = None,
        property_object_typedef_path: PathLike | None = None,
        property_object_typecache: TypeCache | None = None,
    ) -> None:
        self.name = name
        self.text = text
        self.dml_type = dml_type
        self.po_decoder = ObjectPropertyDecoder(
            typedef_path=property_object_typedef_path,
            type_cache=property_object_typecache,
            flags=property_object_flags,
            property_mask=property_object_mask,
            exhaustive=property_object_exhaustive,
        )
        self.noxfer = noxfer

    def is_property_object(self) -> bool:
        """
        is_property_object returns `True` if the field describes a property object.
            This is determined by the presence of the additional `property_object_...`
            fields in the constructor having non-`None` values.

        Returns:
            bool: True if the field represents a property_object
        """

        return self.po_decoder.params_are_complete()

    def can_decode_property_object(self) -> bool:
        """
        can_decode_property_object returns `True` if the internal decoder
        is able to deserialize a property object represented by the field's
        value. If the FieldDef does not represent a property object, this
        returns `False`.

        Returns:
            bool: `True` if a property object can be decoded from a `Field`
        """

        return self.is_property_object() and self.po_decoder.can_deserialize()

    def decode_represented_property_object(
        self, field: "Field"
    ) -> DynamicObject | None:
        """
        decode_represented_property_object decodes te corresponding `Field`'s
            value into a property object if possible.

        Args:
            field (Field): message field instance

        Raises:
            ValueError: If this definition does not define a property object
            AttributeError: If the provided `Field`'s value is not stored as bytes

        Returns:
            DynamicObject | None: property object if successfully decoded or
                `None` if failed under some circumstances
        """

        if not self.can_decode_property_object():
            raise ValueError("Does not define a property object")
        if not isinstance(field.value, bytes):
            raise AttributeError("Field value is not stored as bytes")

        return self.po_decoder.deserialize(field.value)

    # TODO: python 11, change to typing.Self
    @classmethod
    def from_xml(cls, node: xml.etree.ElementTree.Element) -> FieldDef:
        """
        from_xml generates a `FieldDef` representation of the message from
            the message definition xml file

        Args:
            node (xml.etree.ElementTree.Element): xml message node (parent of
                the RECORD tag)

        Returns:
            FieldDef: representation of the message definition xml
        """

        return cls(
            name=node.tag,
            text=(node.text or "").strip(),
            dml_type=DMLType.from_str(node.attrib.get("TYPE")),
            property_object_flags=DMLType.from_str(node.attrib.get("PO_FLAGS")),
            property_object_mask=node.attrib.get("PO_MASK"),
            property_object_exhaustive=node.attrib.get("PO_EXHAUSTIVE"),
            noxfer=(node.attrib.get("NOXFER") == "TRUE"),
        )


class Field:
    """
    Specific instance of a DML field as defined by its `FieldDef`.

    Fields representing object property objects are not automatically
    unserialized. To get the represented property object, use `as_property_object`
    """

    def __init__(self, value: Any, field_def: FieldDef) -> None:
        self.value = value
        self.definition = field_def

    def is_property_object(self) -> bool:
        """
        is_property_object alias for `Field#definition.is_property_object()`

        Returns:
            bool: `True` if the field describes a property object
        """

        self.definition.is_property_object()

    def as_property_object(self):
        return self.definition.decode_represented_property_object(field=self)


class DMLMessage(BaseMessage):
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
        super.__init__(DMLService)
        self.fields = fields
        self.protocol_id = protocol_id
        self.protocol_desc = protocol_desc
        self.msg_id = msg_id
        self.msg_desc = msg_desc
        self.source = source


class DMLMessageDef(BaseMessageDecoder):
    """Defines a DML interface message and its structure.
    Provides a deserializer for the represented message."""

    def __init__(
        self,
        protocol,
        xml_def: xml.etree.ElementTree.Element,
        order: int | None = None,
    ):
        """Initializes a DML message definition from an XML definition

        Args:
            protocol (DMLProtocol): Parent protocol`
            id (int): id/order number
            xml_record (Element): "Record" XML Element to load
        """
        # The assigned id (order) to the message
        self.order = order
        # Parent protocol
        self.protocol = protocol
        self.name = xml_def.tag
        self.desc = None
        self.handler = None
        self.fields = []
        # only one child ever exists, the record tag
        for field in list(xml_def[0]):
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
                dirty_type = field.attrib.get("TYPE")
                dirty_type = dirty_type or field.attrib.get("TYP")
                dirty_type = dirty_type or field.attrib.get("TPYE")
                if dirty_type is None:
                    # how does this even work in the live game?!
                    logging.warning(
                        "A DML field was found without a type. "
                        "Since there's only one known place this happens in the "
                        "current files, assuming it's the GlobalID missing the GID type"
                    )
                    # safety check in case this ever expands
                    assert field_map["name"] == "GlobalID"
                    field_map["type"] = DMLType.GID
                elif dirty_type == "UBYTE":
                    # this is because KI never learned to use a spellchecker
                    field_map["type"] = DMLType.UBYT
                else:
                    # the selector is also because KI never learned to use a spellchecker
                    field_map["type"] = DMLType.from_str(dirty_type)

                field_map["property_obj_flags"] = DMLType.from_str(
                    field.attrib.get("PO_FLAGS")
                )
                field_map["property_obj_mask"] = field.attrib.get("PO_MASK")
                field_map["property_obj_exhaustive"] = field.attrib.get("PO_EXHAUSTIVE")
                field_map["noxfer"] = field.attrib.get("NOXFER") == "TRUE"
                self.fields.append(field_map)

    def field_def(self, name: str) -> map:  # sourcery skip: use-next
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
        reader: BytestreamReader | bytes,
        has_ki_header=False,
        has_dml_header=False,
        **kwargs,
    ) -> DMLMessage:
        if has_ki_header:
            # advance past ki header and message header
            reader.advance(PACKET_HEADER_LEN)
        elif has_dml_header:
            reader.advance(DML_HEADER_LEN)

        decoded_fields = []
        for field in self.fields:
            DMLField = namedtuple(field["name"], ["name", "value", "src_encoding"])
            value = reader.read(field["type"])
            decoded_fields.append(DMLField(field["name"], value, field["type"]))

        return DMLMessage(decoded_fields, msg_id=self.order, msg_desc=self.desc)

    def __str__(self) -> str:
        return f"{self.order}: {self.name}"

    def __repr__(self) -> str:
        return f"""DMLMessageDef:
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
            if msg.order is not None:
                return msg.order
            assert msg.name
            return msg.name

        # sort and assign ids based on ordinal (ASCII chart) order
        defs.sort(key=msg_key)

        # assign ids
        id_map = {}
        for i, dml_def in enumerate(defs, start=1):
            if dml_def.order != None and i != dml_def.order:
                raise Exception("Bad order to id conversion caught")
            dml_def.order = i

            id_map[i] = dml_def

        return id_map


class DMLService:
    def parse_dml_file(self, filename: PathLike) -> None:
        """Loads the protocol according to the given xml

        Args:
            filename (str): [Protocol to load]
        """
        import xml.etree.ElementTree as ET

        tree = ET.parse(filename)
        root = tree.getroot()
        message_blocks = []

        # store protocol block as our own instance vars, not as a block
        metadata_block = root.find("_ProtocolInfo/RECORD")
        self.id = int(metadata_block.find("ServiceID").text)
        self.type = metadata_block.find("ProtocolType").text
        self.version = int(metadata_block.find("ProtocolVersion").text)
        self.description = metadata_block.find("ProtocolDescription").text

        for block in list(root):
            # this isn't a message definition
            if block.tag == "_ProtocolInfo":
                continue
            # FIXME id should be held by protocol since it's determined in relation
            # to other messages. Avoid data duping.
            message_blocks.append(DMLMessageDef(protocol=self, xml_def=block))

        # sort the message blocks and assign their record id
        self.message_map = DMLMessageDef.list_to_id_map(message_blocks)

        # update child ids

    def __init__(self, filename: PathLike | None = None) -> None:
        self.id: int = None
        self.type: str = None
        self.version: int = None
        self.description: str = None
        self.message_map: Dict[int, DMLMessageDef] = {}
        if filename:
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
            service_id = reader.read(DMLType.UBYT)
            if service_id != self.id:
                raise Exception("Invalid protocol for this message")

        message_id: int = reader.read(DMLType.UBYT)
        len: int = reader.read(DMLType.USHRT)
        try:
            dml_object: DMLMessage = self.message_map[message_id].decode_message(reader)
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


class DMLProtocol(MessageProtocol):
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
    ) -> DMLMessage:
        if type(reader) == bytes:
            reader = BytestreamReader(reader)
        if has_ki_header:
            reader.advance(PACKET_HEADER_LEN)
        service_id = reader.peek(DMLType.UBYT)
        if service_id not in self.protocol_map:
            raise ValueError(f"unknown dml protocol: {service_id}")
        return self.protocol_map[service_id].decode_dml_service(
            reader, has_service_id=True
        )
