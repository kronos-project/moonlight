import json
from os import PathLike
from typing_extensions import Self
from printrospector import BinarySerializer, TypeCache
from copy import copy


class ObjectPropertyDecoder:
    
    def __init__(
        self,
        typedef_path: PathLike,
        flags: int,
        exhaustive: bool,
        property_mask: int = 24,
    ) -> None:
        self.property_mask = property_mask
        self.flags = flags
        self.exhaustive = exhaustive
        self.reload_typedefs(typedef_path)

    def reload_typedefs(self, typedef_path: PathLike):
        self.__typedef_path = typedef_path
        with open(self.__typedef_path, encoding="utf-8") as f:
            self.type_cache = TypeCache(json.load(f))
        self.serializer = BinarySerializer(self.type_cache, self.flags, self.exhaustive)

    def deserialize(self, property_mask):
        return self.serializer.deserialize(self.bites, property_mask=property_mask)

    def brute_force(self, bites: bytes):
        serializer_clone = copy(self.serializer)
        for flags in range(pow(2, 5)):
            serializer_clone.serializer_flags = flags
            try:
                obj = serializer_clone.deserialize(bites, self.property_mask)
                if obj and len(obj.items()) > 0:
                    return obj
            except:
                next
        return None
