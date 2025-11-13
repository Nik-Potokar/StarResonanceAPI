package ncap

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type InterfaceStats struct {
	Name        string `json:"name"`
	Desc        string `json:"desc"`
	PacketCount int    `json:"packet_count"`
	ByteCount   int64  `json:"byte_count"`
}

// GetActiveNetworkCards gets currently active network cards
func GetActiveNetworkCards(devices []pcap.Interface, autoCheckTime int) *InterfaceStats {
	if len(devices) == 0 {
		log.Fatal("No network cards found")
	}
	checkTime := autoCheckTime
	if 1 > checkTime {
		checkTime = 3
	}
	log.Println(fmt.Sprintf("Starting to monitor all network card traffic, please wait %d seconds", checkTime))
	stats := make(map[string]*InterfaceStats)
	done := make(chan bool)
	for _, device := range devices {
		stats[device.Name] = &InterfaceStats{
			Name:        device.Name,
			Desc:        device.Description,
			PacketCount: 0,
			ByteCount:   0,
		}
		go monitorInterface(device.Name, stats[device.Name], done)
	}
	time.Sleep(time.Duration(checkTime) * time.Second)
	close(done) // Close channel

	time.Sleep(100 * time.Millisecond)

	var maxPackets int
	var maxBytes int64
	var activeInterface *InterfaceStats

	for _, stat := range stats {
		if stat.PacketCount > maxPackets || (stat.PacketCount == maxPackets && stat.ByteCount > maxBytes) {
			maxPackets = stat.PacketCount
			maxBytes = stat.ByteCount
			activeInterface = stat
		}
	}
	if activeInterface != nil && activeInterface.PacketCount > 0 {
		return activeInterface
	} else {
		return nil
	}
}

func monitorInterface(deviceName string, stats *InterfaceStats, done chan bool) {
	// Open network card for packet capture
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		// Some network cards may not be openable, silently ignore
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-done:
			return
		case packet := <-packets:
			if packet != nil {
				stats.PacketCount++
				stats.ByteCount += int64(len(packet.Data()))
			}
		}
	}
}
