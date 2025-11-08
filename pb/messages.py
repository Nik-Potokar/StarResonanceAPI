"""
Simplified protobuf message classes
These classes provide minimal compatibility with the protobuf messages
used in the Go version. For a full implementation, generate from bp.proto.
"""
from google.protobuf.message import Message
from google.protobuf.internal import decoder, encoder, wire_format
from typing import List, Optional
from enum import IntEnum


class EDisappearType(IntEnum):
    """Disappear type enum"""
    EDisappearDead = 1


class EEntityType(IntEnum):
    """Entity type enum"""
    EntMonster = 2


class EDamageType(IntEnum):
    """Damage type enum"""
    Heal = 2


def read_varint(data: bytes, pos: int = 0) -> tuple:
    """
    Read a varint from bytes

    Returns:
        (value, new_position)
    """
    value, new_pos = decoder._DecodeVarint(data, pos)
    return value, new_pos


def read_string(data: bytes) -> tuple:
    """
    Read a length-prefixed string

    Returns:
        (string, bytes_consumed)
    """
    if len(data) == 0:
        return "", 0

    try:
        length, pos = read_varint(data, 0)
        if pos + length > len(data):
            return "", 0
        string_value = data[pos:pos + length].decode('utf-8')
        return string_value, pos + length
    except:
        return "", 0


# Simple message classes that can parse protobuf data
class Vector3:
    """3D Vector"""

    def __init__(self):
        self.x: float = 0.0
        self.y: float = 0.0
        self.z: float = 0.0

    def GetX(self) -> float:
        return self.x

    def GetY(self) -> float:
        return self.y

    def GetZ(self) -> float:
        return self.z

    def ParseFromString(self, data: bytes):
        """Parse from protobuf bytes"""
        pos = 0
        while pos < len(data):
            try:
                tag, pos = read_varint(data, pos)
            except:
                break

            field_num = tag >> 3
            wire_type = tag & 0x7

            if field_num == 1 and wire_type == 5:  # x (fixed32)
                if pos + 4 <= len(data):
                    import struct
                    self.x = struct.unpack('<f', data[pos:pos + 4])[0]
                    pos += 4
            elif field_num == 2 and wire_type == 5:  # y (fixed32)
                if pos + 4 <= len(data):
                    import struct
                    self.y = struct.unpack('<f', data[pos:pos + 4])[0]
                    pos += 4
            elif field_num == 3 and wire_type == 5:  # z (fixed32)
                if pos + 4 <= len(data):
                    import struct
                    self.z = struct.unpack('<f', data[pos:pos + 4])[0]
                    pos += 4
            else:
                # Skip unknown field
                if wire_type == 0:  # varint
                    _, pos = read_varint(data, pos)
                elif wire_type == 1:  # fixed64
                    pos += 8
                elif wire_type == 2:  # length-delimited
                    length, pos = read_varint(data, pos)
                    pos += length
                elif wire_type == 5:  # fixed32
                    pos += 4
                else:
                    break


class AttrData:
    """Attribute data"""

    def __init__(self):
        self.id: Optional[int] = None
        self.raw_data: Optional[bytes] = None

    def GetId(self) -> int:
        return self.id if self.id is not None else 0

    @property
    def RawData(self) -> bytes:
        return self.raw_data if self.raw_data is not None else b''


class AttrCollection:
    """Collection of attributes"""

    def __init__(self):
        self.attrs: List[AttrData] = []

    def GetAttrs(self) -> List[AttrData]:
        return self.attrs


class DisappearEntity:
    """Entity that disappeared"""

    def __init__(self):
        self.uuid: int = 0
        self.disappear_type: int = 0

    def GetUuid(self) -> int:
        return self.uuid

    def GetDisappearType(self) -> int:
        return self.disappear_type


class Entity:
    """Entity information"""

    def __init__(self):
        self.Uuid: int = 0
        self.EntityType: int = 0
        self.Attrs: Optional[AttrCollection] = None


class SyncNearEntities:
    """Sync near entities message"""

    def __init__(self):
        self.Appear: List[Entity] = []
        self.Disappear: List[DisappearEntity] = []

    def ParseFromString(self, data: bytes):
        """Parse from protobuf bytes"""
        # This is a simplified parser
        # For full implementation, use protoc to generate from .proto
        pass

    def GetAppear(self) -> List[Entity]:
        return self.Appear

    def GetDisappear(self) -> List[DisappearEntity]:
        return self.Disappear


class CharBase:
    """Character base info"""

    def __init__(self):
        self.fight_point: int = 0
        self.name: str = ""

    def GetFightPoint(self) -> int:
        return self.fight_point

    def GetName(self) -> str:
        return self.name


class RoleLevel:
    """Role level info"""

    def __init__(self):
        self.Level: int = 0


class AttrInfo:
    """Attribute info"""

    def __init__(self):
        self.cur_hp: int = 0
        self.max_hp: int = 0

    def GetCurHp(self) -> int:
        return self.cur_hp

    def GetMaxHp(self) -> int:
        return self.max_hp


class SceneData:
    """Scene data"""

    def __init__(self):
        self.map_id: int = 0
        self.line_id: int = 0

    def GetMapId(self) -> int:
        return self.map_id

    def GetLineId(self) -> int:
        return self.line_id


class VData:
    """Container V data"""

    def __init__(self):
        self.CharId: int = 0
        self.CharBase: Optional[CharBase] = None
        self.Attr: Optional[AttrInfo] = None
        self.SceneData: Optional[SceneData] = None
        self.role_level: Optional[RoleLevel] = None

    def GetRoleLevel(self) -> Optional[RoleLevel]:
        return self.role_level


class SyncContainerData:
    """Sync container data message"""

    def __init__(self):
        self.VData: Optional[VData] = None

    def ParseFromString(self, data: bytes):
        """Parse from protobuf bytes"""
        pass


class DamageInfo:
    """Damage information"""

    def __init__(self):
        self.owner_id: Optional[int] = None
        self.top_summoner_id: int = 0
        self.attacker_uuid: int = 0
        self.is_dead: bool = False
        self.type: int = 0
        self.damage_pos: Optional[Vector3] = None

    def GetTopSummonerId(self) -> int:
        return self.top_summoner_id

    def GetAttackerUuid(self) -> int:
        return self.attacker_uuid

    def GetIsDead(self) -> bool:
        return self.is_dead

    def GetType(self) -> int:
        return self.type


class SkillEffects:
    """Skill effects"""

    def __init__(self):
        self.Damages: List[DamageInfo] = []


class AoiSyncDelta:
    """AOI sync delta"""

    def __init__(self):
        self.uuid: int = 0
        self.Attrs: Optional[AttrCollection] = None
        self.SkillEffects: Optional[SkillEffects] = None

    def GetUuid(self) -> int:
        return self.uuid

    def GetSkillEffects(self) -> Optional[SkillEffects]:
        return self.SkillEffects


class DeltaInfo:
    """Delta info"""

    def __init__(self):
        self.Uuid: Optional[int] = None
        self.BaseDelta: Optional[AoiSyncDelta] = None

    def GetUuid(self) -> int:
        return self.Uuid if self.Uuid is not None else 0

    def GetBaseDelta(self) -> Optional[AoiSyncDelta]:
        return self.BaseDelta


class SyncToMeDeltaInfo:
    """Sync to me delta info"""

    def __init__(self):
        self.DeltaInfo: Optional[DeltaInfo] = None

    def ParseFromString(self, data: bytes):
        """Parse from protobuf bytes"""
        pass


class SyncNearDeltaInfo:
    """Sync near delta info"""

    def __init__(self):
        self.DeltaInfos: List[AoiSyncDelta] = []

    def ParseFromString(self, data: bytes):
        """Parse from protobuf bytes"""
        pass
