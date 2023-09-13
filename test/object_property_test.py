import pytest
from moonlight.net import DMLType, DMLField, DMLFieldDef, ObjectPropertyDecoder
from .fixtures import character_property_object, create_character_field_def, typecache
import struct


def test_character_data(
    character_property_object: bytes, create_character_field_def, typecache
):
    field_def = create_character_field_def
    field_def.po_decoder.set_typecache(typecache, "FIXTURES")
    field = DMLField(character_property_object, field_def)
    field.definition.po_decoder.exhaustive = False
    field.definition.po_decoder.flags = 0
    field.definition.po_decoder.property_mask = 24
    po = field.as_property_object()

    assert po is not None
    # main object
    assert po.name == "class WizardCharacterCreationInfo"
    assert po["m_templateID"] == 1
    assert po["m_name"] == ""
    assert po["m_shouldRename"] is False
    assert po["m_globalID"] == 0
    assert po["m_userID"] == 0
    assert po["m_quarantined"] is False
    assert po["m_equipmentInfoList"] is None
    assert po["m_location"] == ""
    assert po["m_level"] == 0
    assert po["m_schoolOfFocus"] == 78318724
    assert po["m_nameIndices"] == 9061448
    # nested avatar behavior
    c_behavior = po["m_avatarBehavior"]
    assert c_behavior.name == "class WizardCharacterBehavior"
    assert c_behavior["m_nHeadHandsModel"] == 0
    assert c_behavior["m_nHairModel"] == 7
    assert c_behavior["m_nHatModel"] == 0
    assert c_behavior["m_nTorsoModel"] == 0
    assert c_behavior["m_nFeetModel"] == 0
    assert c_behavior["m_nWandModel"] == 0
    assert c_behavior["m_nSkinColor"] == 2
    assert c_behavior["m_nSkinDecal"] == 0
    assert c_behavior["m_nHairColor"] == 70
    assert c_behavior["m_nHatColor"] == 5
    assert c_behavior["m_nHatDecal"] == 6
    assert c_behavior["m_nTorsoColor"] == 5
    assert c_behavior["m_nTorsoDecal"] == 6
    assert c_behavior["m_nTorsoDecal2"] == 0
    assert c_behavior["m_nTorsoDecal2"] == 0
    assert c_behavior["m_nFeetColor"] == 5
    assert c_behavior["m_nFeetDecal"] == 6
    assert c_behavior["m_eGender"] == "enum eGender::Female"
    assert c_behavior["m_eRace"] == "enum eRace::Human"
    assert c_behavior["m_afterCombatDance"] == 0
    assert c_behavior["m_nSkinDecal2"] == 11
    assert c_behavior["m_extendedHairColor"] == 0
    assert c_behavior["m_extendedSkinDecal"] == 0
    assert c_behavior["m_newPlayerOptions"] == 1900022819
    assert c_behavior["m_newPlayerOptions2"] == 9
