"""Implementation of the human representation mixin"""

from types import LambdaType
from typing import Any, Tuple


class HumanReprMixin:
    """
    Mixin providing `as_human_dict`, a utility to translate an object into a
    human-friendly dict interpretation.

    HumanReprMixin is designed as to not need overriding of `as_human_dict`
    under most circumstances. Using the following class constants, the behavior
    and handling of desired object attributes can be changed.

    `HUMAN_REPR_IGNORE`: Tuple[str] of object attributes to never include in
    the resulting dictionary.

    `HUMAN_REPR_SYNTHETIC`: dict[str, LambdaType] of synthetic attributes to
    include in the resulting dictionary. Each lambda is called with `self` as
    an argument and inserts the result as is. Objects implementing
    `HumanReprMixin` will not automatically be converted and the lambda should
    call it explicitly.

    `HUMAN_REPR_COMPACT_IGNORE`: Tuple[str] of object attributes to exclude
    from the resulting dictionary if compact is set to `True`

    `HUMAN_REPR_RENAME`: dict[str, str] where attributes of the name `key`
    are instead included in the resulting dictionary with the name `value`.
    This does not apply to synthetic or static values.

    `HUMAN_REPR_REPR_ON_COMPACT`: bool where when `True` and `compact` mode
    is requested, the object's `__repr__` will be returned instead of the
    normal dictionary. Defaults to `False`.

    `HUMAN_REPR_ORDER_PREPEND`: Tuple[str] of resulting dictionary keys. If a given key
    is in the final dictionary, these keys will be first in the order given.
    Any keys not specified will be after these. Keys renamed via
    `HUMAN_REPR_RENAME` will need to be given with their new name,
    not the original.

    `HUMAN_REPR_ORDER_APPEND`: Tuple[str] of resulting dictionary keys. If a
    given key is in the final dictionary, these keys will always be last in the
    order given. Any keys not specified will be before these. Keys renamed via
    `HUMAN_REPR_RENAME` will need to be given with their new name, not the
    original.

    Example:
           @dataclass(init=True)
           class ADataclass(HumanReprMixin):
               HUMAN_REPR_IGNORE = ("ignore_me")
               HUMAN_REPR_COMPACT_IGNORE = ("sometimes_ignore_me")
               HUMAN_REPR_RENAME = {"an_abv": "annoying_abbreviation"}
               HUMAN_REPR_ORDER_PREPEND = ("me_first", "me_second")
               HUMAN_REPR_ORDER_APPEND = ("me_last")
               HUMAN_REPR_SYNTHETIC = {"im_not_real": lambda x: x.__name__}

               ignore_me: bool
               include_me: bool
               sometimes_ignore_me: bool
               me_first: bool
               me_second: bool
               me_last: bool
               an_abv: str

           >> obj.as_human_dict(compact=False)
           {
               "me_first": True,
               "me_second": True,
               "include_me": True,
               "im_not_real": "ADataclass",
               "annoying_abbreviation": "WYSIWYG",
               "me_last"
           }
    """

    HUMAN_REPR_IGNORE: Tuple[str] = ()
    HUMAN_REPR_SYNTHETIC: dict[str, LambdaType] = {}
    HUMAN_REPR_STATIC: dict[str, Any] = {}
    HUMAN_REPR_COMPACT_IGNORE: Tuple[str] = ()
    HUMAN_REPR_RENAME: dict[str, str] = {}
    HUMAN_REPR_REPR_ON_COMPACT: bool = False
    HUMAN_REPR_ORDER_PREPEND: Tuple[str] = ()
    HUMAN_REPR_ORDER_APPEND: Tuple[str] = ()

    def as_human_dict(self, compact=True) -> Any:
        """
        Using class variables as defined in `HumanReprMixin`, returns a dict
        of the current object
        """
        keypairs: dict[str, Any] = {}

        if self.HUMAN_REPR_REPR_ON_COMPACT:
            return repr(self)

        for key, val in vars(self).items():
            if key in self.HUMAN_REPR_IGNORE:
                continue
            if compact and key in self.HUMAN_REPR_COMPACT_IGNORE:
                continue

            # turn any HRM attribute into its dict first
            if isinstance(val, HumanReprMixin):
                # replace output name if requested
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = val.as_human_dict(
                    compact=compact
                )
            # convert any HRM objects within list or dict attributes
            elif isinstance(val, list):
                tmp = []
                for subitem in val:
                    if isinstance(subitem, HumanReprMixin):
                        tmp.append(subitem.as_human_dict(compact=compact))
                    else:
                        tmp.append(subitem)
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = tmp
            elif isinstance(val, dict):
                tmp = {}
                for subkey, subvalue in val.items():
                    if isinstance(subvalue, HumanReprMixin):
                        tmp[subkey] = subvalue.as_human_dict(compact=compact)
                    else:
                        tmp[subkey] = subvalue
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = tmp
            else:
                # anything else is left to the whims of what's outputting the end dict
                keypairs[self.HUMAN_REPR_RENAME.get(key, key)] = val

        for key, val in self.HUMAN_REPR_SYNTHETIC.items():
            try:
                if compact and key in self.HUMAN_REPR_COMPACT_IGNORE:
                    continue
                tmp = val(self)
                keypairs[key] = val(self)
            # we don't want synthetics in an invalid state to cause a crash
            # attribute and value errors are possible here
            except Exception as err:  # pylint: disable=broad-except
                keypairs[key] = f"Failed: {err}"

        for key, val in self.HUMAN_REPR_STATIC:
            keypairs[key] = val

        # no need to do reordering if not requested
        if not self.HUMAN_REPR_ORDER_PREPEND and not self.HUMAN_REPR_ORDER_APPEND:
            return keypairs

        keypairs_sorted: dict[str, Any] = {}
        for ordered_key in self.HUMAN_REPR_ORDER_PREPEND:
            if ordered_key in keypairs:
                keypairs_sorted[ordered_key] = keypairs[ordered_key]

        # include unordered keys
        # the order they're defined controls most printing systems
        for key, value in keypairs.items():
            if key not in self.HUMAN_REPR_ORDER_APPEND:
                keypairs_sorted[key] = value

        # and finally ordered to append
        for key, value in keypairs.items():
            if key in self.HUMAN_REPR_ORDER_APPEND:
                keypairs_sorted[key] = value

        return keypairs_sorted
