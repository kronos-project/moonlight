from .human_repr import HumanReprMixin
from .serde_mixin import SerdeMixin, SerdeJSONEncoder


def bytes_to_pretty_str(bites: bytes) -> str:
    return bites.hex(" ").upper()


# def try_to(obj: Any, )
