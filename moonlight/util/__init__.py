"""Project utilities"""

from .serde_mixin import SerdeMixin, SerdeJSONEncoder


def bytes_to_pretty_str(bites: bytes) -> str:
    """
    bytes_to_pretty_str takes a bytestring and turns it into pretty-printable
        hexadecimal such as "15 CE 6F"

    Args:
        bites (bytes): data to pretty-print

    Returns:
        str: pretty hexadecimal bytes
    """
    return bites.hex(" ").upper() if bites else ""


# def try_to(obj: Any, )
