import json
from os import PathLike
from typing_extensions import Self
from printrospector import BinarySerializer, TypeCache

def build_property_object_serde(typefile: PathLike, flags=0, exhaustive=False):
    with open(typefile, encoding="utf-8") as f:
        type_cache = TypeCache(json.load(f))

    return BinarySerializer(type_cache, flags, False)


    # class PropertyObjectSerdeChain:
    #     def __init__(self, type_cache, flags, exhaustive) -> None:
    #         self.type_cache = type_cache
    #         self.flags = flags
    #         self.exhaustive = exhaustive
        
    #     def with_flags(self, flags) -> Self:
    #         self.flags = flags
    #         return self
        
    #     def with_exhaustive(self, exhaustive) -> Self:
    #         self.exhaustive = exhaustive
    #         return self
        
    #     def deserialize(self, data: bytes):
    #         return BinarySerializer(self.type_cache, self.flags, self.exhaustive)

    

    
        
        

# # First, we need a type cache so that printrospector learns the types it may encounter.
# with open("path/to/types.json", encoding="utf-8") as f:
#     type_cache = TypeCache(json.load(f))

# # Construct a new serializer instance in primitive mode without any flags.
# # We give it the previously crafted type_cache for identification of objects.
# serializer = BinarySerializer(type_cache, 0, False)

# # Now we can deserialize our character creation data.
# char = serializer.deserialize(ZORA_TIGERWALD)

# # The resulting object behaves very much like a dictionary:
# assert char["m_templateID"] == 1
