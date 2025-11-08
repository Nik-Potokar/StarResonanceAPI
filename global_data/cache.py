"""
Global cache for scene monsters and player data
"""
import threading
import time
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class Position:
    """3D Position"""
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0


@dataclass
class AttackPlayer:
    """Player attacking a monster"""
    name: str = ""
    last_attack_time: int = 0


@dataclass
class Monster:
    """Monster/Enemy data"""
    name: str = ""
    hp: int = 0
    max_hp: int = 0
    pos: Optional[Position] = None
    template_id: int = 0
    entity_id: int = 0
    attack_players: Dict[int, AttackPlayer] = field(default_factory=dict)
    update_time: int = 0


@dataclass
class SceneData:
    """Scene information"""
    map_id: int = 0
    name: str = ""
    line_id: int = 0


@dataclass
class ScenePlayer:
    """Player information in scene"""
    id: int = 0
    fight_point: int = 0
    name: str = ""
    level: int = 0
    hp: int = 0
    max_hp: int = 0
    pos: Optional[Position] = None


@dataclass
class SceneInfo:
    """Complete scene information"""
    scene: SceneData = field(default_factory=SceneData)
    player: ScenePlayer = field(default_factory=ScenePlayer)


# Global state
scene_monster_list: Dict[int, Monster] = {}
scene_monster_list_lock = threading.RLock()

current_scene: Optional[SceneInfo] = None
current_scene_lock = threading.RLock()


def clear_all_data():
    """Clear all cached data"""
    clear_monster_list()


def clear_monster_list():
    """Clear monster list"""
    global scene_monster_list
    with scene_monster_list_lock:
        scene_monster_list = {}


def find_monster_id(uuid: int, callback: Callable[[Monster], None]):
    """
    Find or create monster by UUID and call callback

    Args:
        uuid: Monster UUID
        callback: Callback function to modify monster
    """
    global scene_monster_list

    # Get or create monster
    with scene_monster_list_lock:
        if uuid in scene_monster_list:
            monster = scene_monster_list[uuid]
            is_new = False
        else:
            monster = Monster(update_time=int(time.time()))
            scene_monster_list[uuid] = monster
            is_new = True

    # Call callback outside lock to avoid deadlock
    start_time = time.time()
    callback(monster)

    # Log performance
    duration = (time.time() - start_time) * 1000
    if duration >= 100:
        print(f"{uuid} 异常更新耗时: {duration:.0f} ms")

    # Update timestamp if not new
    if not is_new:
        with scene_monster_list_lock:
            if uuid in scene_monster_list:
                scene_monster_list[uuid].update_time = int(time.time())


def update_scene(callback: Callable[[SceneInfo], None]):
    """
    Update scene information

    Args:
        callback: Callback function to modify scene
    """
    global current_scene

    with current_scene_lock:
        if current_scene is None:
            current_scene = SceneInfo()
        callback(current_scene)
