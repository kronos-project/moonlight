from os.path import *
import pytest

this_folder = dirname(__file__)


def load_to_bytes(*f_path):
    full_f_path = join(*f_path)
    with open(full_f_path, "rb") as f:
        return f.read()


def load_packet(*f_path):
    return load_to_bytes(this_folder, "packets", *f_path)


@pytest.fixture
def control_session_offer():
    return load_packet("ctrl_session_offer.bin")


@pytest.fixture
def control_session_accept():
    return load_packet("ctrl_session_accept.bin")


@pytest.fixture
def dml_leave_lot():
    return load_packet("dml_leave_lot.bin")


@pytest.fixture
def dml_update_poi():
    return load_packet("dml_update_poi.bin")
