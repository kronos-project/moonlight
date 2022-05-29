"""
Message implementation for netpack flagtool
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from .common import DMLType, Message


@dataclass(kw_only=True)
class FlagtoolMessage(Message):
    """
    FlagtoolMessage is an implementation of the netpack flagtool network
    traffic payload. When in a packet capture from libnetpack, these messages
    can be recognized and parsed into a usable form.
    """

    serializer_hash: int
    flags: int
    serializer_flags: int
    is_save: bool
    is_exhaustive: bool
    serializer_type: str

    def as_serde_dict(self, **kwargs) -> dict[str, Any] | Any:
        """
        See `SerdeMixin#as_serde_dict`
        """
        return {
            **super().as_serde_dict(**kwargs),
            "data": {
                "format": "FLAGTOOL",
                "name": type(self).__name__,
                "fields": {
                    "serializer_hash": {
                        "value": self.serializer_hash,
                        "format": DMLType.UINT32.as_serde_dict(**kwargs),
                    },
                    "flags": {
                        "value": self.flags,
                        "format": DMLType.UINT32.as_serde_dict(**kwargs),
                    },
                    "serializer_flags": {
                        "value": self.serializer_flags,
                        "format": DMLType.UINT32.as_serde_dict(**kwargs),
                    },
                    "is_save": {
                        "value": self.is_save,
                        "format": DMLType.BOOL.as_serde_dict(**kwargs),
                    },
                    "is_exhaustive": {
                        "value": self.is_exhaustive,
                        "format": DMLType.BOOL.as_serde_dict(**kwargs),
                    },
                    "serializer_type": {
                        "value": self.serializer_type,
                        "format": DMLType.UINT8.as_serde_dict(**kwargs),
                    },
                },
            },
        }

    @classmethod
    def from_bytes(cls, bites: bytes) -> FlagtoolMessage:
        """
        from_bytes unpacks a message from its payload format into a FlagtoolMessage

        Args:
            bites (bytes): message payload

        Raises:
            ValueError: provided payload does not describe a flagtool message

        Returns:
            _type_: _description_
        """

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
