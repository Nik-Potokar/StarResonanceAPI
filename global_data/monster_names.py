"""
Monster names mapping
"""
import json
import os

monster_names: dict = {}


def init_monster_names():
    """Load monster names from JSON file"""
    global monster_names

    # Get the path to monster_names.json
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    json_path = os.path.join(parent_dir, "global", "monster_names.json")

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            monster_names = json.load(f)
        print(f"怪物映射表加载完成,加载数量: {len(monster_names)}")
    except Exception as e:
        print(f"加载怪物映射表解析错误: {e}")
        raise
