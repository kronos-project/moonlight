"""
Parser for DML message definitions and parsing messages based on them
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from os import PathLike
from typing import Any, Dict, List

from printrospector.object import DynamicObject
from printrospector.type_cache import TypeCache

from .common import (
    DML_HEADER_LEN,
    PACKET_HEADER_LEN,
    BytestreamReader,
    DMLType,
    HumanReprMixin,
    Message,
    PacketHeader,
)

from .property_object import PropertyObjectDecoder, build_typecache

SERVICE_ID_SIZE = 1
MESSAGE_ID_SIZE = 1

logger = logging.getLogger(__name__)


class FieldDef(HumanReprMixin):
    """
    Definition of a DML field within a message. Used to hold the represented
    xml from message definition files as well as property object decoding
    information.
    """

    HUMAN_REPR_IGNORE = "po_decoder"

    # FIXME reduce number of fields. It's okay for now since this isn't
    # part of the public api.
    def __init__(  # pylint: disable=too-many-arguments
        self,
        name: str,
        dml_type: DMLType,
        property_object_flags: int | None = None,
        property_object_mask: int | None = None,
        property_object_exhaustive: bool | None = None,
        noxfer: bool | None = None,
        property_object_typedef_path: PathLike | None = None,
        property_object_typecache: TypeCache | None = None,
    ) -> None:
        self.name = name
        self.dml_type = dml_type
        self.po_decoder = PropertyObjectDecoder(
            typedef_path=property_object_typedef_path,
            typecache=property_object_typecache,
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
    def from_xml(cls, node: ET.Element) -> FieldDef:
        """
        from_xml generates a `FieldDef` representation of the message from
            the message definition xml file

        Args:
            node (xml.etree.ElementTree.Element): xml message node (parent of
                the RECORD tag)

        Returns:
            FieldDef: representation of the message definition xml
        """
        exhaustive = node.attrib.get("PO_EXHAUSTIVE")
        if exhaustive is None:
            pass
        elif exhaustive == "TRUE":
            exhaustive = True
        else:
            exhaustive = False

        return cls(
            name=node.tag,
            dml_type=DMLType.from_str(node.attrib.get("TYPE")),
            property_object_flags=node.attrib.get("PO_FLAGS"),
            property_object_mask=node.attrib.get("PO_MASK"),
            property_object_exhaustive=exhaustive,
            noxfer=(node.attrib.get("NOXFER") == "TRUE"),
        )

    def to_human_dict(self, compact=False) -> dict[str, Any] | str:
        output = {
            "name": self.name,
            "dml_type": self.dml_type.t_name,
        }
        if not compact:
            output["noxfer"] = self.noxfer
        if compact or not self.po_decoder or not self.po_decoder.params_are_complete():
            return output

        output["po_flags"] = self.po_decoder.flags
        output["po_exhaustive"] = self.po_decoder.exhaustive
        output["po_property_mask"] = self.po_decoder.property_mask

        return output

    def __repr__(self) -> str:
        return f"<FieldDef '{self.name}({self.dml_type})'>"


class Field(HumanReprMixin):
    """
    Specific instance of a DML field as defined by its `FieldDef`.

    Fields representing object property objects are not automatically
    unserialized. To get the represented property object, use `as_property_object`
    """

    HUMAN_REPR_IGNORE = ("value", "definition")
    HUMAN_REPR_COMPACT_IGNORE = "noxfer"
    HUMAN_REPR_ORDER_PREPEND = ("name", "value", "dml_type")
    HUMAN_REPR_SYNTHETIC = {
        "value": lambda x: x.as_property_object()
        if x.is_property_object()
        else x.value,
        "name": lambda x: x.name(),
        "dml_type": lambda x: x.dml_type().as_human_dict(),
        "noxfer": lambda x: x.noxfer(),
    }

    def __init__(self, value: Any, field_def: FieldDef) -> None:
        self.value = value
        self.definition = field_def

    def is_property_object(self) -> bool:
        """
        is_property_object alias for `Field#definition.is_property_object()`

        Returns:
            bool: `True` if the field describes a property object
        """

        return self.definition.is_property_object()

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

    def noxfer(self):
        return self.definition.noxfer

    def to_human_dict(self) -> dict:
        return {
            "value": self.as_property_object()
            if self.is_property_object()
            else self.value,
            "definition": self.definition.to_human_dict(),
        }

    def as_human_dict(self, compact=True) -> dict[str, Any] | str:
        human_dict = super().as_human_dict(compact)
        if self.is_property_object():
            human_dict["value"] = self.as_property_object()
        return human_dict

    def __str__(self) -> str:
        if self.is_property_object():
            return f"{self.value} (property object)"
        return str(self.value)

    def __repr__(self) -> str:
        return f"Field(value={self.value}, field_def={repr(self.definition)})"


# FIXME: grab protocol stuff from definition
@dataclass(init=True, repr=True, kw_only=True)
class DMLMessage(Message):
    HUMAN_REPR_IGNORE = "definition"
    HUMAN_REPR_SYNTHETIC = {
        "protocol_id": lambda x: x.protocol().id,
        "protocol_desc": lambda x: x.protocol().desc,
        "name": lambda x: x.name(),
        "desc": lambda x: x.desc(),
    }
    HUMAN_REPR_COMPACT_IGNORE = (
        "protocol",
        "protocol_id",
        "protocol_desc",
        "order_id",
        "header",
    )
    HUMAN_REPR_ORDER_PREPEND = (
        *Message.HUMAN_REPR_ORDER_PREPEND,
        "name",
        "desc",
        "protocol_id",
        "protocol_desc",
        "order_id",
        "fields",
    )

    fields: List[Field]
    definition: DMLMessageDef
    original_bytes: bytes = None
    order_id: int = None

    def name(self):
        return self.definition.name

    def desc(self):
        return self.definition.desc

    def protocol(self):
        return self.definition.protocol

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


class DMLMessageDef(HumanReprMixin):
    """Defines a DML interface message and its structure.
    Provides a deserializer for the represented message."""

    def __init__(
        self,
        protocol: DMLProtocol,
        xml_def: ET.Element,
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
            field_map = {"name": xml_field.tag}
            dirty_type = xml_field.attrib.get("TYPE")
            dirty_type = dirty_type or xml_field.attrib.get("TYP")
            dirty_type = dirty_type or xml_field.attrib.get("TPYE")
            if dirty_type is None:
                # how does this even work in the live game?!
                logger.warning(
                    "A DML field was found without a type. "
                    "Since there's only one known place this happens in the "
                    "current files, assuming it's the GlobalID missing the GID type"
                )
                # safety check in case this ever expands
                assert field_map["name"] == "GlobalID"
                field_map["dml_type"] = DMLType.GID
            elif dirty_type == "UBYTE":
                # again, i don't understand how these even work in-game
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

    def reload_protocol_typedefs(self, typecache, typedef_path):
        for field in self.fields:
            field.po_decoder.set_typecache(typecache, typedef_path)

    def decode_message(
        self,
        reader: BytestreamReader | bytes,
        has_ki_header=False,
        has_dml_header=False,
        packet_bytes: bytes = None,
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

        return DMLMessage(
            fields=decoded_fields,
            definition=self,
            original_bytes=packet_bytes,
            order_id=self.order_id,
        )

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
            if msg.order_id is not None:
                return msg.order_id
            assert msg.name
            return msg.name.encode()

        # sort and assign ids based on ordinal (ASCII chart) order
        defs.sort(key=msg_key)

        # assign ids
        id_map = {}
        for i, dml_def in enumerate(defs, start=1):
            if dml_def.order_id is not None and i != dml_def.order_id:
                raise ValueError("Bad order to id conversion caught")
            dml_def.order_id = i

            id_map[i] = dml_def

        return id_map


class DMLProtocol:
    def parse_dml_file(self, filename: PathLike) -> None:
        """Loads the protocol according to the given xml

        Args:
            filename (str): [Protocol to load]
        """

        tree = ET.parse(filename)
        root = tree.getroot()
        message_defs: List[DMLMessageDef] = []

        # store protocol block as our own instance vars, not as a block
        metadata_block = root.find("_ProtocolInfo/RECORD")
        self.id = int(metadata_block.find("ServiceID").text)
        self.type = metadata_block.find("ProtocolType").text
        self.version = int(metadata_block.find("ProtocolVersion").text)
        self.desc = metadata_block.find("ProtocolDescription").text

        known_names = set()
        for block in list(root):
            if block.tag == "_ProtocolInfo":
                continue
            # KI has a habit of just pasting messages in more than once...
            if block.tag in known_names:
                logger.warning(
                    "Duplicate message definition '%s' found within protocol %d",
                    block.tag,
                    self.id,
                )
                continue
            message_defs.append(DMLMessageDef(protocol=self, xml_def=block))
            known_names.add(block.tag)

        # sort the message blocks and assign their record id
        self.message_map = DMLMessageDef.list_to_id_map(message_defs)

    def __init__(self, filename: PathLike | None = None) -> None:
        self.id: int = None  # pylint: disable=invalid-name
        self.type: str = None
        self.version: int = None
        self.desc: str = None
        self.message_map: Dict[int, DMLMessageDef] = {}
        if filename:
            self.parse_dml_file(filename)

    def decode_bytes(
        self,
        bites: BytestreamReader,
        original_bites: bytes = None,
        has_protocol_id=False,
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
        if has_protocol_id:
            service_id = bites.read(DMLType.UBYT)
            if service_id != self.id:
                raise ValueError(bites, "Invalid protocol for this message")

        message_id: int = bites.read(DMLType.UBYT)
        message_len: int = bites.read(DMLType.USHRT)
        try:
            dml_object: DMLMessage = self.message_map[message_id].decode_message(
                bites, packet_bytes=original_bites
            )
        except ValueError as err:
            logger.error(
                'Failed to decode message. err: "%s", protocol_id: %d, msg_id: %d, packet_data: %s',
                err,
                self.id,
                message_id,
                original_bites,
            )
            return None
        if dml_object is not None:
            dml_object.protocol_id = self.id
            dml_object.protocol_desc = self.desc
        return dml_object


class DMLProtocolRegistry:
    def __init__(self, *protocol_files, typedef_path: PathLike | None = None) -> None:
        self.protocol_map: Dict[int, DMLProtocol] = {}
        self.typedef_path = typedef_path
        self.typedef_cache: TypeCache = None

        for file in protocol_files:
            try:
                self.load_service(file)
            except ValueError as err:
                raise ValueError("Failed to load dml protocol definition") from err

        if typedef_path:
            raise NotImplementedError

    def load_service(self, protocol_file):
        protocol = DMLProtocol(protocol_file)
        logger.debug("loaded protocol %d: %s", protocol.id, protocol.desc)
        for msg in protocol.message_map.values():
            logger.debug("\t%s", repr(msg))
        self.protocol_map[protocol.id] = protocol

    def get_by_id(self, id: int):
        return self.protocol_map[id]

    def load_typedef(self, typedef_path: PathLike):
        cache = build_typecache(typedef_path)
        for protocol in self.protocol_map.values():
            for msg in protocol.message_map.values():
                msg.reload_protocol_typedefs(cache, typedef_path)

    def decode_packet(
        self,
        bites: bytes,
    ) -> DMLMessage:
        original_bites = bites
        bites = BytestreamReader(bites)
        ki_header = PacketHeader(bites)

        protocol_id = bites.read(DMLType.UBYT)
        if protocol_id not in self.protocol_map:
            raise ValueError(f"unknown dml protocol: {protocol_id}")

        msg = self.get_by_id(protocol_id).decode_bytes(
            bites,
            original_bites=original_bites,
        )
        if msg:
            msg.packet_header = ki_header
            # TODO move original bites assignment here
        return msg
