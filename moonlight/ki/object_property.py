"""
Object property parsing things
"""

import json
from copy import copy
import logging
from os import PathLike

from printrospector import BinarySerializer, DynamicObject, TypeCache


class ObjectPropertyDecoder:
    """
    Wrapper for printrospector's parser that abstracts needing to deal with
    managing both a serializer and typedef cache
    """

    #
    def __init__(  # pylint: disable=too-many-arguments
        self,
        flags: int,
        exhaustive: bool,
        property_mask: int = 24,
        typedef_path: PathLike | None = None,
        type_cache: TypeCache | None = None,
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

        self.property_mask = property_mask
        self.flags = flags
        self.exhaustive = exhaustive
        self.__typedef_path = typedef_path
        self.type_cache = type_cache
        if type_cache and typedef_path:
            logging.warning(
                "Both TypeCache and path to typedef.json were "
                "provided to field. Using provided TypeCache first."
            )
        elif typedef_path:
            self.load_typedefs(typedef_path)

    def load_typedefs(self, typedef_path: PathLike):
        """
        load_typedefs Loads a new typedef cache from the given path

        Args:
            typedef_path (PathLike): path to wizwalker typedef json file
        """

        self.__typedef_path = typedef_path
        with open(self.__typedef_path, encoding="utf-8") as file:
            self.type_cache = TypeCache(json.load(file))
        self.serializer = BinarySerializer(self.type_cache, self.flags, self.exhaustive)

    def deserialize(self, bites: bytes) -> DynamicObject | None:
        """
        deserialize deserializes a bytestring into a property object based on
        the current settings

        Args:
            bites (bytes): serialized property object

        Returns:
            DynamicObject | None: deserialized property object or None if failed
        """

        return self.serializer.deserialize(bites, property_mask=self.property_mask)

    def brute_force(self, bites: bytes) -> DynamicObject | None:
        """
        brute_force attempts to brute force the serialization flags on a property
        object. Results will vary.

        Args:
            bites (bytes): serialized property object

        Returns:
            DynamicObject | None: deserialized property object if successful, otherwise None
        """

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
