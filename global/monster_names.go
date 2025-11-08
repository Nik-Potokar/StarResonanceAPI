package global

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"log"
)

//go:embed monster_names.json
var MonsterNamesJson string

var MonsterNames map[uint64]string

func InitMonsterNames() {
	if err := json.Unmarshal(bytes.NewBufferString(MonsterNamesJson).Bytes(), &MonsterNames); err != nil {
		log.Fatalln("Failed to parse monster mapping table: ", err.Error())
	}
	log.Println("Monster mapping table loaded, count: ", len(MonsterNames))
}
