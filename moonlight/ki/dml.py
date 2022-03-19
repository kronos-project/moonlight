"""
Parser for DML message definitions and parsing messages based on them
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree
from collections import namedtuple
from dataclasses import dataclass, fields
from ensurepip import version
from os import PathLike
from typing import Any, Dict, List, Union

from printrospector.object import DynamicObject
from printrospector.type_cache import TypeCache

from moonlight.ki.net_common import (DML_HEADER_LEN, PACKET_HEADER_LEN,
                                     BaseMessage, BaseMessageDecoder,
                                     BytestreamReader, DMLType, MessageProtocol)

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

    def as_property_object(self) -> DynamicObject | None:
        """
        as_property_object Takes the field value as it currently is and returns
            it as a property object if possible

        Returns:
            DynamicObject | None: Property object representation of the field
        """
        return self.definition.decode_represented_property_object(field=self)

    def name(self):
        return self.definition.name
    
    def dml_type(self):
        return self.definition.dml_type


@dataclass
class DMLMessage(BaseMessage):
    def __init__(
        self,
        fields: List[Field],
        protocol_id: int = None,
        order_id: str = None,
        protocol_order: int = None,
        msg_desc: str = None,
        source: str = None,
    ):
        super().__init__(protocol_class=DMLService, original_bytes="")
        self.fields = fields
        self.protocol_id = protocol_id
        self.protocol_desc = order_id
        self.order_id = protocol_order
        self.msg_desc = msg_desc
        self.source = source

    def get_val(self, field_name):
        for field in self.fields:
            if field.name == field_name:
                return field.value
        raise AttributeError

    def get_field_def(self, field_name):
        for field in self.fields:
            if field.name == field_name:
                return field
        raise AttributeError

class DMLMessageDef(BaseMessageDecoder):
    """Defines a DML interface message and its structure.
    Provides a deserializer for the represented message."""

    def __init__(
        self,
        protocol,
        xml_def: xml.etree.ElementTree.Element,
        order_id: int | None = None,
    ):
        """Initializes a DML message definition from an XML definition

        Args:
            protocol (DMLProtocol): Parent protocol`
            order (int): id/order number
            xml_def (Element): XML Element to load (parent of RECORD)
        """

        # The assigned id (order) to the message
        self.order_id = order_id
        # Parent protocol
        self.protocol = protocol
        # that _MsgName field? It's often wrong.
        # #KI_Problems
        self.name = xml_def.tag
        self.desc = None
        self.handler = None
        self.fields: List[FieldDef] = []
        # only one child ever exists, the record tag
        xml_record = xml_def.find("RECORD")

        self.desc = xml_record.find("_MsgDescription").text
        self.handler = xml_record.find("_MsgHandler").text
        # We intentionally ignore "_MsgName" because it can be wrong
        # Game doesn't care.
        self.order_id = xml_record.find("_MsgOrder")
        if self.order_id is not None:
            self.order_id = int(self.order_id.text)

        for xml_field in xml_record:
            if xml_field.tag.startswith("_"):
                continue
            field_map = {"name": xml_field.tag, "text": (xml_field.text or "").strip()}
            dirty_type = xml_field.attrib.get("TYPE")
            dirty_type = dirty_type or xml_field.attrib.get("TYP")
            dirty_type = dirty_type or xml_field.attrib.get("TPYE")
            if dirty_type is None:
                # how does this even work in the live game?!
                logging.warning(
                    "A DML field was found without a type. "
                    "Since there's only one known place this happens in the "
                    "current files, assuming it's the GlobalID missing the GID type"
                )
                # safety check in case this ever expands
                assert field_map["name"] == "GlobalID"
                field_map["dml_type"] = DMLType.GID
            elif dirty_type == "UBYTE":
                # again, i don't understand how these even work ingame
                field_map["dml_type"] = DMLType.UBYT
            else:
                field_map["dml_type"] = DMLType.from_str(dirty_type)

            field_map["property_object_flags"] = DMLType.from_str(
                xml_field.attrib.get("PO_FLAGS")
            )
            field_map["property_object_mask"] = xml_field.attrib.get("PO_MASK")
            field_map["property_object_exhaustive"] = xml_field.attrib.get(
                "PO_EXHAUSTIVE"
            )
            field_map["noxfer"] = xml_field.attrib.get("NOXFER") == "TRUE"
            self.fields.append(FieldDef(**field_map))

    def get_field(self, name: str) -> map:  # sourcery skip: use-next
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

        decoded_fields = [
            Field(field_def=field_def, value=reader.read(field_def.dml_type))
            for field_def in self.fields
        ]

        return DMLMessage(decoded_fields, order_id=self.order_id, msg_desc=self.desc)

    def __str__(self) -> str:
        return f"{self.order_id}: {self.name}"

    def __repr__(self) -> str:
        return f"""DMLMessageDef:
            order = {self.order_id}
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
                raise ValueError("Bad order to id conversion caught")
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
        message_defs: List[DMLMessageDef] = []

        # store protocol block as our own instance vars, not as a block
        metadata_block = root.find("_ProtocolInfo/RECORD")
        self.id = int(metadata_block.find("ServiceID").text)
        self.type = metadata_block.find("ProtocolType").text
        self.version = int(metadata_block.find("ProtocolVersion").text)
        self.description = metadata_block.find("ProtocolDescription").text

        message_defs.extend(
            DMLMessageDef(protocol=self, xml_def=block)
            for block in list(root)
            if block.tag != "_ProtocolInfo"
        )

        # sort the message blocks and assign their record id
        self.message_map = DMLMessageDef.list_to_id_map(message_defs)

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
        except Exception as err:
            logging.error(
                "Failed to decode message. "
                f'err: "{err}" '
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
            try:
                self.load_service(f)
            except ValueError as err:
                raise ValueError("Failed to load xml message definition") from err

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
