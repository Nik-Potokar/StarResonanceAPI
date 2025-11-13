package main

import (
	_ "embed"
	"flag"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/balrogsxt/StarResonanceAPI/global"
	"github.com/balrogsxt/StarResonanceAPI/ncap"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

var (
	networkCard   = flag.String("network", "", "Enter network card full description, auto for automatic selection")
	port          = flag.Int("port", 8989, "Default API port")
	expireTime    = flag.Int64("expire", 10, "Data expiration time (seconds), default 10s")
	autoCheckTime = flag.Int("autoCheckTime", 3, "Auto check active network card time (seconds)")
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("Program crashed: %v\nStack trace:\n%s", r, debug.Stack())
		}
	}()
	flag.Parse()
	log.Println("Github: https://github.com/balrogsxt/StarResonanceAPI")
	var deviceName = *networkCard
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Failed to get network cards: ", err.Error())
	}
	if deviceName == "auto" {
		log.Println("Automatically finding active network card, please wait...")
		active := ncap.GetActiveNetworkCards(devices, *autoCheckTime)
		if active != nil {
			log.Println("Automatically found suitable network card: ", active.Desc)
			log.Println("Monitored packet count: ", active.PacketCount)
			log.Println("Monitored packet traffic: ", fmt.Sprintf("%d bytes (%.2f KB)", active.ByteCount, float64(active.ByteCount)/1024))
			deviceName = active.Desc
		}
	}
	if deviceName == "" {
		var option string
		options := make([]string, 0)
		for _, device := range devices {
			options = append(options, device.Description)
		}
		prompt := &survey.Select{
			Message: "Unable to automatically find active network card, please manually select (you can find the description in your network settings):",
			Options: options,
		}
		err := survey.AskOne(prompt, &option)
		if err != nil {
			log.Fatalf("Selection error: %s", err.Error())
		}
		if len(option) == 0 {
			log.Fatalf("Network card selection is empty")
		}
		deviceName = option
	}

	// Load monster JSON list
	global.InitMonsterNames()

	// Start services
	go Openapi()
	go OpenCap(deviceName)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Program started, press Ctrl+C to exit")
	<-sigChan
	log.Println("Shutting down...")
}

func OpenCap(deviceName string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Packet capture service crashed: %v\nStack trace:\n%s", r, debug.Stack())
			log.Println("API server will continue running. Press Ctrl+C to exit.")
		}
	}()

	// Create packet capture core
	capCore := ncap.NewCapCore()
	if err := capCore.Start(deviceName); err != nil {
		log.Printf("ERROR: Failed to start packet capture: %v", err)
		log.Println("API server will continue running. Press Ctrl+C to exit.")
		// Don't use Fatalf - let the API server continue running
		return
	}
}
func Openapi() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("API service crashed: %v\nStack trace:\n%s", r, debug.Stack())
		}
	}()

	gin.SetMode(gin.ReleaseMode)
	s := gin.New()

	// Add global panic recovery middleware
	s.Use(gin.Recovery())

	s.GET("/api/enemies", func(ctx *gin.Context) {
		global.SceneMonsterListLock.RLock()
		defer global.SceneMonsterListLock.RUnlock()
		et := *expireTime
		if 0 >= et {
			et = 10
		}
		list := make(map[uint64]*global.Monster)
		for id, item := range global.SceneMonsterList {
			if time.Now().Unix()-item.UpdateTime > et {
				continue // Ignore data not updated in the last N seconds
			}
			attackPlayers := make(map[uint64]*global.AttackPlayer)
			if item.AttackPlayers != nil {
				for uid, player := range item.AttackPlayers {
					if time.Now().Unix()-player.LastAttackTime > et { // Ignore players not in combat in the last N seconds
						continue
					}
					attackPlayers[uid] = player
				}
			}
			if len(item.Name) > 0 || (item.Hp >= 0 && item.MaxHp > 0) {
				monsterCopy := *item
				monsterCopy.AttackPlayers = attackPlayers
				list[id] = &monsterCopy
			}
		}
		ctx.JSON(200, gin.H{
			"code":  0,
			"msg":   "OK",
			"enemy": list,
		})
	})
	s.GET("/api/clear", func(ctx *gin.Context) {
		global.ClearAllData()
		ctx.JSON(200, gin.H{
			"code": 0,
			"msg":  "OK",
		})
	})
	s.GET("/api/scene", func(ctx *gin.Context) {
		global.CurrentSceneLock.RLock()
		defer global.CurrentSceneLock.RUnlock()
		ctx.JSON(200, gin.H{
			"code": 0,
			"msg":  "OK",
			"data": global.CurrentScene,
		})
	})
	log.Println(fmt.Sprintf("Service started at: http://127.0.0.1:%d", *port))
	if err := s.Run(fmt.Sprintf(":%d", *port)); err != nil {
		log.Printf("ERROR: API server failed: %s", err.Error())
		log.Println("Please check if the port is already in use or restart the application.")
		// Don't use Fatalf - let the panic recovery handle it
		return
	}
}
