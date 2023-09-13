import pytest
from moonlight.net import (
    ControlMessage,
    ControlProtocol,
    KIHeader,
)
from .fixtures import *


@pytest.fixture
def control_protocol():
    return ControlProtocol()


def test_session_offer(control_protocol: ControlProtocol, control_session_offer): # type: ignore
    header = KIHeader.from_bytes(control_session_offer)
    message = control_protocol.decode_packet(
        control_session_offer, header, has_ki_header=True
    )
    assert message.OPCODE == 0
    assert message.session_id == 1419
    assert message.signed_msg_len == 281
    assert message.unix_timestamp_millis_into_second == 276
    assert message.unix_timestamp_seconds == 1639851252
    assert message.signed_msg == (b"\xFF" * 281)


def test_session_accept(control_protocol, control_session_accept):
    header = KIHeader.from_bytes(control_session_accept)
    message = control_protocol.decode_packet(
        control_session_accept, header, has_ki_header=True
    )
    assert message.OPCODE == 5
    assert message.reserved_start == 0
    assert message.session_id == 1419
    assert message.signed_msg_len == 257
    assert message.unix_timestamp_millis_into_second == 288
    assert message.unix_timestamp_seconds == 1639851231
    assert message.signed_msg == (b"\xff" * 257)
