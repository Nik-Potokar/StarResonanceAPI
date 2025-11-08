"""
REST API server
"""
import time
from flask import Flask, jsonify
from global_data import cache


def create_app(expire_time: int = 10):
    """
    Create Flask application

    Args:
        expire_time: Data expiration time in seconds

    Returns:
        Flask app instance
    """
    app = Flask(__name__)

    @app.route('/api/enemies', methods=['GET'])
    def get_enemies():
        """Get enemy/monster data"""
        with cache.scene_monster_list_lock:
            et = max(expire_time, 1)
            result_list = {}

            for monster_id, monster in cache.scene_monster_list.items():
                # Ignore data not updated in expire_time seconds
                if time.time() - monster.update_time > et:
                    continue

                # Filter attack players
                attack_players = {}
                if monster.attack_players:
                    for uid, player in monster.attack_players.items():
                        # Ignore players who haven't attacked in expire_time seconds
                        if time.time() - player.last_attack_time > et:
                            continue
                        attack_players[uid] = {
                            "name": player.name
                        }

                # Only include monsters with valid data
                if monster.name or (monster.hp >= 0 and monster.max_hp > 0):
                    monster_data = {
                        "entity_id": monster.entity_id,
                        "name": monster.name,
                        "hp": monster.hp,
                        "max_hp": monster.max_hp,
                        "template_id": monster.template_id,
                        "attack_players": attack_players
                    }

                    # Add position if available
                    if monster.pos:
                        monster_data["pos"] = {
                            "x": monster.pos.x,
                            "y": monster.pos.y,
                            "z": monster.pos.z
                        }

                    result_list[monster_id] = monster_data

            return jsonify({
                "code": 0,
                "msg": "OK",
                "enemy": result_list
            })

    @app.route('/api/clear', methods=['GET'])
    def clear_data():
        """Clear all data"""
        cache.clear_all_data()
        return jsonify({
            "code": 0,
            "msg": "OK"
        })

    @app.route('/api/scene', methods=['GET'])
    def get_scene():
        """Get current scene information"""
        with cache.current_scene_lock:
            scene_data = None

            if cache.current_scene:
                player_data = None
                if cache.current_scene.player:
                    player_data = {
                        "id": cache.current_scene.player.id,
                        "fight_point": cache.current_scene.player.fight_point,
                        "name": cache.current_scene.player.name,
                        "level": cache.current_scene.player.level,
                        "hp": cache.current_scene.player.hp,
                        "max_hp": cache.current_scene.player.max_hp
                    }

                    # Add position if available
                    if cache.current_scene.player.pos:
                        player_data["pos"] = {
                            "x": cache.current_scene.player.pos.x,
                            "y": cache.current_scene.player.pos.y,
                            "z": cache.current_scene.player.pos.z
                        }

                scene_info = None
                if cache.current_scene.scene:
                    scene_info = {
                        "map_id": cache.current_scene.scene.map_id,
                        "name": cache.current_scene.scene.name,
                        "line_id": cache.current_scene.scene.line_id
                    }

                scene_data = {
                    "scene": scene_info,
                    "player": player_data
                }

            return jsonify({
                "code": 0,
                "msg": "OK",
                "data": scene_data
            })

    return app


def run_api(port: int = 8989, expire_time: int = 10):
    """
    Run API server

    Args:
        port: Port to listen on
        expire_time: Data expiration time
    """
    app = create_app(expire_time)
    print(f"服务启动在: http://127.0.0.1:{port}")

    try:
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
    except Exception as e:
        print(f"API服务错误: {e}")
        raise
