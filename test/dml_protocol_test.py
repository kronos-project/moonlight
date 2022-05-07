import os
from os.path import isfile, join
from posix import listdir

from moonlight.net import DMLProtocolRegistry
from .fixtures import load_packet

import pytest
from moonlight.net import DMLType


@pytest.fixture
def dml_protocol() -> DMLProtocolRegistry:
    res_folder = os.path.join(os.path.dirname(__file__), "fixtures", "dml", "messages")
    protocols = [f for f in listdir(res_folder) if isfile(join(res_folder, f))]
    protocols = map(lambda x: join(res_folder, x), protocols)
    return DMLProtocolRegistry(*protocols)


def test_decode_dml(dml_protocol: DMLProtocolRegistry):
    bites = load_packet("dml_proto1_fake.bin")
    obj = dml_protocol.decode_packet(bites)
    assert obj is not None
    assert obj.order_id == 1
    assert obj.protocol().id == 1
    assert obj.desc() == "I needed fake definitions"
    assert obj.protocol().desc == "FAKE MESSAGES 1"
    assert len(obj.fields) == 19
    assert obj.fields[0].name() == "TestField_00_INT8"
    assert obj.fields[1].name() == "TestField_01_UINT8"
    assert obj.fields[2].name() == "TestField_02_INT16"
    assert obj.fields[3].name() == "TestField_03_UINT16"
    assert obj.fields[4].name() == "TestField_04_INT32"
    assert obj.fields[5].name() == "TestField_05_UINT32"
    assert obj.fields[6].name() == "TestField_06_FLOAT32"
    assert obj.fields[7].name() == "TestField_07_UINT64"
    assert obj.fields[8].name() == "TestField_08_BYT"
    assert obj.fields[9].name() == "TestField_09_UBYT"
    assert obj.fields[10].name() == "TestField_0A_SHRT"
    assert obj.fields[11].name() == "TestField_0B_USHRT"
    assert obj.fields[12].name() == "TestField_0C_INT"
    assert obj.fields[13].name() == "TestField_0D_UINT"
    assert obj.fields[14].name() == "TestField_0E_FLT"
    assert obj.fields[15].name() == "TestField_0F_DBL"
    assert obj.fields[16].name() == "TestField_10_GID"
    assert obj.fields[17].name() == "TestField_11_STR"
    assert obj.fields[18].name() == "TestField_12_STR"

    assert obj.fields[0].value == 0
    assert obj.fields[1].value == 16
    assert obj.fields[2].value == 8480
    assert obj.fields[3].value == 12592
    assert obj.fields[4].value == 1128415552
    assert obj.fields[5].value == 1397903696
    assert obj.fields[6].value == 4.175980768877802e21
    assert obj.fields[7].value == 8608196880778817904
    assert obj.fields[8].value == -128
    assert obj.fields[9].value == 144
    assert obj.fields[10].value == -24160
    assert obj.fields[11].value == 45488
    assert obj.fields[12].value == -1010646592
    assert obj.fields[13].value == 3553808848
    assert obj.fields[14].value == -8.370480339423351e21
    assert obj.fields[15].value == -7.581280411902108e269
    assert obj.fields[16].value == 506097522914230528
    assert obj.fields[17].value == "FOOBAR"
    assert obj.fields[18].value == b"abc123\xed\xee\xef"

    assert obj.fields[0].dml_type() is DMLType.INT8
    assert obj.fields[1].dml_type() is DMLType.UINT8
    assert obj.fields[2].dml_type() is DMLType.INT16
    assert obj.fields[3].dml_type() is DMLType.UINT16
    assert obj.fields[4].dml_type() is DMLType.INT32
    assert obj.fields[5].dml_type() is DMLType.UINT32
    assert obj.fields[6].dml_type() is DMLType.FLOAT32
    assert obj.fields[7].dml_type() is DMLType.UINT64
    assert obj.fields[8].dml_type() is DMLType.BYT
    assert obj.fields[9].dml_type() is DMLType.UBYT
    assert obj.fields[10].dml_type() is DMLType.SHRT
    assert obj.fields[11].dml_type() is DMLType.USHRT
    assert obj.fields[12].dml_type() is DMLType.INT
    assert obj.fields[13].dml_type() is DMLType.UINT
    assert obj.fields[14].dml_type() is DMLType.FLT
    assert obj.fields[15].dml_type() is DMLType.DBL
    assert obj.fields[16].dml_type() is DMLType.GID
    assert obj.fields[17].dml_type() is DMLType.STR
    assert obj.fields[18].dml_type() is DMLType.STR
