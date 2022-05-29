from __future__ import annotations

from json import JSONEncoder
from types import LambdaType
from typing import Any, Tuple


class SerdeMixin:
    SERDE_TRANSIENT: Tuple[str] = ()
    SERDE_TRANSFORM: dict[str, Tuple[LambdaType, LambdaType]]
    SERDE_SYNTHETIC: dict[str, LambdaType]
    SERDE_RENAME: dict[str, str]

    def as_serde_dict(self, **kwargs) -> Any:
        keypairs: dict[str, Any] = {}

        for key, val in vars(self).items():

            # turn any SM attribute into its dict first
            if isinstance(val, SerdeMixin):
                # replace output name if requested
                keypairs[self.SERDE_RENAME.get(key, key)] = val.as_serde_dict(**kwargs)
            # convert any SM objects within list or dict attributes
            elif isinstance(val, list):
                tmp = []
                for subitem in val:
                    if isinstance(subitem, SerdeMixin):
                        tmp.append(subitem.as_serde_dict(**kwargs))
                    else:
                        tmp.append(subitem)
                keypairs[self.SERDE_RENAME.get(key, key)] = tmp
            elif isinstance(val, dict):
                tmp = {}
                for subkey, subvalue in val.items():
                    if isinstance(subvalue, SerdeMixin):
                        tmp[subkey] = subvalue.as_serde_dict(**kwargs)
                    else:
                        tmp[subkey] = subvalue
                keypairs[self.SERDE_RENAME.get(key, key)] = tmp
            else:
                # anything else is left to the whims of what's outputting the end dict
                keypairs[self.SERDE_RENAME.get(key, key)] = val

        for key, val in self.SERDE_SYNTHETIC.items():
            keypairs[key] = val(self)

        return keypairs

    @classmethod
    def from_serde_dict(cls, data: Any, ctx: dict[str, Any] = None) -> SerdeMixin:
        if ctx is None:
            ctx = {}

    # @classmethod
    # def from_serde_dict(cls):
    #     raise NotImplementedError


class SerdeJSONEncoder(JSONEncoder):
    def __init__(self, indent: int = None, **kwargs):
        super().__init__(indent=indent)
        self.passthrough: dict = kwargs

    def default(self, o):
        if isinstance(o, SerdeMixin):
            return o.as_serde_dict(**self.passthrough)
        elif isinstance(o, dict):
            tmp = {}
            for key, value in o.items():
                if isinstance(value, SerdeMixin):
                    tmp[key] = value.as_serde_dict(**self.passthrough)
                else:
                    tmp[key] = value.__dict__
            return tmp
        elif isinstance(o, list):
            tmp = []
            for val in o:
                if isinstance(val, SerdeMixin):
                    tmp.append(val.as_serde_dict(**self.passthrough))
                else:
                    tmp.append(val.__dict__)
            return tmp
        return o.__dict__
