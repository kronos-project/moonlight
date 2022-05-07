import xml.etree.ElementTree as ET
from os import chdir
from os.path import *

import pytest
from moonlight.net.dml import FieldDef
from moonlight.net.object_property import build_typecache

this_folder = dirname(__file__)


def load_to_bytes(*f_path):
    full_f_path = join(*f_path)
    with open(full_f_path, "rb") as f:
        return f.read()


def load_packet(*f_path):
    return load_to_bytes(this_folder, "packets", *f_path)


@pytest.fixture
def character_property_object():
    return load_to_bytes(this_folder, "object_property", "character_data.bin")


@pytest.fixture
def create_character_field_def() -> ET.Element:
    tree = ET.fromstring(
        '<CreationInfo TYPE="STR" PO_FLAGS="0" PO_MASK="24" PO_EXHAUSTIVE="false"></CreationInfo>'
    )
    return FieldDef.from_xml(tree)


@pytest.fixture
def typecache():
    return build_typecache(
        join(this_folder, "object_property", "r707528_Wizard_1_460.json")
    )


@pytest.fixture
def control_session_offer():
    return load_packet("ctrl_session_offer.bin")


@pytest.fixture
def control_session_accept():
    return load_packet("ctrl_session_accept.bin")
