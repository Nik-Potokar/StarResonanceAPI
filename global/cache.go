package global

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Scene monster data
var SceneMonsterList = make(map[uint64]*Monster)
var SceneMonsterListLock = sync.RWMutex{}

var CurrentScene *SceneInfo = nil
var CurrentSceneLock = sync.RWMutex{}

type SceneInfo struct {
	Scene  *SceneData   `json:"scene"`  // Current scene info
	Player *ScenePlayer `json:"player"` // Current scene player info
}
type SceneData struct {
	MapId  uint32 `json:"map_id"`  // Scene ID
	Name   string `json:"name"`    // Scene name
	LineId uint32 `json:"line_id"` // Scene line ID
}
type ScenePlayer struct {
	Id         uint64    `json:"id"`            // Player ID
	FightPoint int32     `json:"fight_point"`   // Combat power
	Name       string    `json:"name"`          // Player nickname
	Level      int32     `json:"level"`         // Player level
	Hp         int64     `json:"hp"`            // Current HP
	MaxHp      int64     `json:"max_hp"`        // Max HP
	Pos        *Position `json:"pos,omitempty"` // Player coordinates
}

type Position struct {
	X float32 `json:"x"`
	Y float32 `json:"y"`
	Z float32 `json:"z"`
}
type AttackPlayer struct {
	Name           string `json:"name,omitempty"` // Player nickname
	LastAttackTime int64  `json:"-"`              // Last attack time
}
type Monster struct {
	Name          string                   `json:"name,omitempty"`           // Monster name
	Hp            uint64                   `json:"hp"`                       // Current HP
	MaxHp         uint64                   `json:"max_hp,omitempty"`         // Max HP
	Pos           *Position                `json:"pos,omitempty"`            // Monster coordinates
	TemplateId    uint64                   `json:"template_id,omitempty"`    // Template ID
	EntityId      uint64                   `json:"entity_id,omitempty"`      // Current enemy ID
	AttackPlayers map[uint64]*AttackPlayer `json:"attack_players,omitempty"` // List of attacking players
	UpdateTime    int64                    `json:"-"`                        // Data last update time
}

func ClearAllData() {
	clearMonsterList()
}
func clearMonsterList() {
	SceneMonsterListLock.Lock()
	defer SceneMonsterListLock.Unlock()
	SceneMonsterList = make(map[uint64]*Monster)
}

//func clearScene() {
//	CurrentSceneLock.Lock()
//	defer CurrentSceneLock.Unlock()
//	// Remove player coordinates, scene switching won't change other info, but network interruption causing server re-identification will clear current scene data
//	if CurrentScene != nil && CurrentScene.Player != nil{
//		CurrentScene.Player.Pos = nil
//	}
//}

func FindMonsterId(uuid uint64, callback func(*Monster)) {
	var monster *Monster
	var isNew bool

	// Lock and get or create monster object
	SceneMonsterListLock.Lock()
	if existing, has := SceneMonsterList[uuid]; has {
		monster = existing
		isNew = false
	} else {
		monster = &Monster{
			UpdateTime: time.Now().Unix(),
		}
		SceneMonsterList[uuid] = monster
		isNew = true
	}
	SceneMonsterListLock.Unlock()

	// Call callback outside lock to avoid deadlock and long lock hold
	startTime := time.Now()
	callback(monster)

	// Record performance metrics
	duration := time.Since(startTime).Milliseconds()
	if duration >= 100 {
		log.Println(fmt.Sprintf("%d Abnormal update time: %d ms", uuid, duration))
	}

	// If not a newly created object, update timestamp
	if !isNew {
		SceneMonsterListLock.Lock()
		if currentMonster, exists := SceneMonsterList[uuid]; exists {
			currentMonster.UpdateTime = time.Now().Unix()
		}
		SceneMonsterListLock.Unlock()
	}
}

func UpdateScene(callback func(*SceneInfo)) {
	CurrentSceneLock.Lock()
	defer CurrentSceneLock.Unlock()
	if CurrentScene == nil {
		CurrentScene = &SceneInfo{
			Player: &ScenePlayer{},
			Scene:  &SceneData{},
		}
	}
	callback(CurrentScene)

}
