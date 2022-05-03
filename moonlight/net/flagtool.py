import struct
from dataclasses import dataclass
from typing import Any

from .common import DMLType, Message


@dataclass(kw_only=True)
class FlagtoolMessage(Message):
    serializer_hash: int
    flags: int
    serializer_flags: int
    is_save: bool
    is_exhaustive: bool
    serializer_type: str

    def as_serde_dict(self) -> dict[str, Any] | Any:
        return {
            **super().as_serde_dict(),
            "data": {
                "format": "FLAGTOOL",
                "name": type(self).__name__,
                "fields": {
                    "serializer_hash": {
                        "value": self.serializer_hash,
                        "format": DMLType.UINT32.as_serde_dict(),
                    },
                    "flags": {
                        "value": self.flags,
                        "format": DMLType.UINT32.as_serde_dict(),
                    },
                    "serializer_flags": {
                        "value": self.serializer_flags,
                        "format": DMLType.UINT32.as_serde_dict(),
                    },
                    "is_save": {
                        "value": self.is_save,
                        "format": DMLType.BOOL.as_serde_dict(),
                    },
                    "is_exhaustive": {
                        "value": self.is_exhaustive,
                        "format": DMLType.BOOL.as_serde_dict(),
                    },
                    "serializer_type": {
                        "value": self.serializer_type,
                        "format": DMLType.UINT8.as_serde_dict(),
                    },
                },
            },
        }

    @classmethod
    def from_bytes(cls, bites: bytes):
        # Copied from https://github.com/kronos-project/netpack/blob/ecdfe34b35acd0dedbf3249a11e2e2783445faa9/scapy_client.py#L45
        try:
            (
                serializer_hash,
                flags,
                serializer_flags,
                is_save,
                is_exhaustive,
                serializer_type,
            ) = struct.unpack("<III??B", bites)
        except Exception as exc:
            raise ValueError("Unable to unpack flagtool msg") from exc

        return cls(
            original_bytes=bites,
            serializer_hash=serializer_hash,
            flags=flags,
            serializer_flags=serializer_flags,
            is_save=is_save,
            is_exhaustive=is_exhaustive,
            serializer_type=serializer_type,
        )
