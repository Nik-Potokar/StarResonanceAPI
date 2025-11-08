# StarResonanceAPI
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-brightgreen.svg)](https://www.gnu.org/licenses/agpl-3.0.txt)

Project based on [StarResonanceDamageCounter](https://github.com/dmlgzs/StarResonanceDamageCounter) implementation to provide more detailed data APIs

### Prerequisites

- npcap


## Startup Method

Launch the exe file from the command line. For custom parameters, refer to the table below.

## Startup Parameters

| Parameter       | Type   | Default | Description                                                        |
|-----------------|--------|---------|---------------------------------------------------------------------|
| --network       | string |         | Network adapter description, use 'auto' for automatic selection     |
| --expire        | int    | 10      | Monster data packet timeout (seconds), monster considered gone/dead if no packet received |
| --port          | int    | 8989    | API service port                                                   |
| --autoCheckTime | int    | 3       | Auto-detect active network adapter wait time (seconds)             |


## API Endpoints
> GET /api/enemies

Get enemy data
```json
{
    "code": 0,
    "msg": "OK",
    "enemy": {
        //Monster Entity ID
        "15247": {
            "name": "Bandit Axeman", //Monster Name
            "hp": 9728, //Current HP
            "max_hp": 10992, //Maximum HP
            "pos": { //Real-time position coordinates
                "x": 191.65988,
                "y": 185.6441,
                "z": 433.85992
            },
            "template_id": 10027, //Monster Template ID
            "entity_id": 15247, //Monster Entity ID
            "attack_players": { //Players currently attacking
                "35321": {
                    "name": "" //Player nickname (not available yet)
                }
            }
        }
    }
}
```

> GET /api/clear

Clear all statistics data

```json
{
  "code": 0,
  "msg": "OK"
}
```

> GET /api/scene

Get current player's scene data

```json
{
    "code": 0,
    "data": { //This is null on first startup, needs map change to populate
        "scene": {
            "map_id": 8, //Map ID
            "name": "Asteris", //Scene Name
            "line_id": 1 //Line/Server ID
        },
        "player": {
            "id": 1000, //Player UID
            "fight_point": 25000, //Combat Rating
            "name": "Player Name",
            "level": 60,
            "hp": 500, //Current HP (not real-time yet)
            "max_hp": 176429, //Maximum HP (not real-time yet)
            "pos": {//Real-time position coordinates
                "x": 106.075485,
                "y": 103.98257,
                "z": 54.675217
            }
        }
    },
    "msg": "OK"
}
```

## Acknowledgments
- [StarResonanceDamageCounter](https://github.com/dmlgzs/StarResonanceDamageCounter)
- [StarResonanceData](https://github.com/PotRooms/StarResonanceData)

## License
[![AGPLv3](https://www.gnu.org/graphics/agplv3-with-text-162x68.png)](LICENSE)

By using this project, you agree to comply with the terms of this license.

This project is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE version 3
