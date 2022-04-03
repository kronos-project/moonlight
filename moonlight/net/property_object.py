"""
Object property parsing things
"""

import json
from copy import copy
import logging
from os import PathLike

from printrospector import BinarySerializer, DynamicObject, TypeCache


def build_typecache(path: PathLike) -> TypeCache:
    with open(path, encoding="utf-8") as file:
        return TypeCache(json.load(file))


def _str_to_int(val):
    return val if val is None else int(val)


class PropertyObjectDecoder:
    """
    Wrapper for printrospector's parser that abstracts needing to deal with
    managing both a serializer and typedef cache
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        flags: int,
        exhaustive: bool,
        property_mask: int = 24,
        typedef_path: PathLike | None = None,
        typecache: TypeCache | None = None,
    ) -> None:
        """
        Args:
            type_cache (TypeCache, optional): Pre-existing loaded typecache.
                Takes precedence over `typedef_path` if both are provided.
            flags (int): Serialization flags for the target property object
            exhaustive (bool): Property object is in exhaustive mode
            property_mask (int, optional): Field mask for the target property object.
                Defaults to 24.
            typedef_path (PathLike, optional): Path to wizwalker typedefs json
        """

        self.property_mask = _str_to_int(property_mask)
        self.flags = _str_to_int(flags)
        self.exhaustive = exhaustive
        self.__typedef_path = typedef_path
        self.typecache = typecache
        self.serializer = None
        if typecache and typedef_path:
            logging.warning(
                "Both TypeCache and path to typedef.json were "
                "provided to field. Using provided TypeCache first."
            )
        elif typedef_path:
            self.load_typedefs_from_file(typedef_path)

    def params_are_complete(self) -> bool:
        """
        params_are_complete returns `True` if the values needed for defining a property
            object are present. In other words, the necessary fields for this
            specific object are present. _This does not include the
            typedef file since they are independent entities._

        Returns:
            bool: Whether or not this decoder has the necessary fields to
                describe a property object. _This does not prove decoding
                is possible as typedefs are independent entities._
        """

        return (
            self.property_mask is not None
            and self.exhaustive is not None
            and self.flags is not None
        )

    def load_typedefs_from_file(self, typedef_path: PathLike):
        """
        load_typedefs_from_file Loads a new typedef cache from the given path

        Args:
            typedef_path (PathLike): path to wizwalker typedef json file
        """

        self.__typedef_path = typedef_path
        with open(self.__typedef_path, encoding="utf-8") as file:
            self.typecache = TypeCache(json.load(file))
        self.serializer = BinarySerializer(self.typecache, self.flags, self.exhaustive)

    def set_typecache(self, cache: TypeCache, sourcepath: PathLike | None = None):
        """
        set_typecache _summary_

        Args:
            cache (TypeCache): _description_
            sourcepath (PathLike | None): Optional sourcepath for visibility's sake
        """
        self.typecache = cache
        self.__typedef_path = sourcepath
        self.serializer = BinarySerializer(self.typecache, self.flags, self.exhaustive)

    def can_deserialize(self) -> bool:
        """
        can_deserialize returns `True` if the object can be deserialized with
            the current information. This means that all serde properties
            are defined and typedefs are loaded.

        Returns:
            bool: `True` if the object can be deserialized
        """

        try:
            self.__verify_deserializer()
        except ValueError:
            return False
        return True

    def deserialize(self, bites: bytes) -> DynamicObject | None:
        """
        deserialize deserializes a bytestring into a property object based on
        the current settings

        Args:
            bites (bytes): serialized property object

        Returns:
            DynamicObject | None: deserialized property object or None if failed
        """

        self.__verify_deserializer()

        return self.serializer.deserialize(bites, property_mask=self.property_mask)

    # FIXME: This is not well protecting itself to ensure serde flags are present
    def brute_force(self, bites: bytes) -> DynamicObject | None:
        """
        brute_force attempts to brute force the serialization flags on a property
        object. Results will vary.

        Args:
            bites (bytes): serialized property object

        Returns:
            DynamicObject | None: deserialized property object if successful, otherwise None
        """

        self.__verify_typecache()

        serializer_clone = copy(self.serializer)
        for flags in range(pow(2, 5)):
            serializer_clone.serializer_flags = flags
            try:
                obj = serializer_clone.deserialize(bites, self.property_mask)
                if obj and len(obj.items()) > 0:
                    return obj
            except:  # pylint: disable=bare-except
                pass
        return None

    def __verify_deserializer(self):
        self.__verify_deserializer_params()
        self.__verify_typecache()

    def __verify_deserializer_params(self):
        if not self.params_are_complete():
            raise ValueError("Cannot deserialize without serde settings")

    def __verify_typecache(self):
        if not self.typecache:
            raise ValueError("Cannot deserialize until a typedef is loaded")