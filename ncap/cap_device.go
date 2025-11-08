package ncap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/balrogsxt/StarResonanceAPI/global"
	"github.com/balrogsxt/StarResonanceAPI/pb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/klauspost/compress/zstd"
)

type CapDevice struct {
	deviceName    string
	device        *pcap.Handle
	currentServer string
	userUid       uint64 // Current player ID

	// TCP reassembly related
	tcpMutex        sync.Mutex
	tcpDataBuffer   []byte
	tcpCacheTime    map[uint32]time.Time
	tcpCache        map[uint32][]byte // Fix: use uint32 to avoid type conversion overflow
	tcpStream       *bytes.Buffer
	tcpNextSeq      uint32 // Fix: use uint32 type
	lastAnyPacketAt time.Time

	// Configuration
	idleTimeout time.Duration
	gapTimeout  time.Duration

	// Server signatures
	serverSignature      []byte
	loginReturnSignature []byte

	packetQueue *Queue[gopacket.Packet]
}

// NewCapDevice creates a new packet capture device
func NewCapDevice(device *pcap.Handle, deviceName string) *CapDevice {
	return &CapDevice{
		deviceName:      deviceName,
		device:          device,
		tcpCache:        make(map[uint32][]byte), // Fix: use uint32
		tcpCacheTime:    make(map[uint32]time.Time),
		tcpDataBuffer:   make([]byte, 0),
		tcpStream:       bytes.NewBuffer(nil),
		tcpNextSeq:      0, // Initialize to 0 instead of -1
		idleTimeout:     10 * time.Second,
		gapTimeout:      2 * time.Second,
		packetQueue:     NewQueue[gopacket.Packet](),
		serverSignature: []byte{0x00, 0x63, 0x33, 0x53, 0x42, 0x00},
		loginReturnSignature: []byte{
			0x00, 0x00, 0x00, 0x62,
			0x00, 0x03,
			0x00, 0x00, 0x00, 0x01,

			0x00, 0x11, 0x45, 0x14,

			0x00, 0x00, 0x00, 0x00,
			0x0a, 0x4e, 0x08, 0x01, 0x22, 0x24,
		},
	}
}

// Start begins packet capture
func (cd *CapDevice) Start() error {
	if cd.device == nil {
		return fmt.Errorf("network device not set")
	}

	// Set filter
	err := cd.device.SetBPFFilter("ip and tcp")
	if err != nil {
		return fmt.Errorf("failed to set filter: %v", err)
	}

	log.Println("Starting packet capture: ", cd.deviceName)

	go func() {
		for {
			if packet, ok := cd.packetQueue.Dequeue(); ok {
				cd.handlePacket(packet)
			} else {
				time.Sleep(time.Millisecond * 50)
			}
		}
	}()

	// Start capturing packets
	packetSource := gopacket.NewPacketSource(cd.device, cd.device.LinkType())
	for packet := range packetSource.Packets() {
		if packet != nil {
			cd.packetQueue.Enqueue(packet)
		} else {
			log.Println("Found empty packet")
		}
	}
	log.Fatalf("Packet channel closed, aborting")
	return nil
}

// handlePacket handles a single packet
func (cd *CapDevice) handlePacket(packet gopacket.Packet) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("handlePacket Panic:", err)
		}
	}()

	if packet == nil {
		log.Println("handlePacket processing data == nil")
		return
	}
	if packet.NetworkLayer() == nil {
		log.Println("NetworkLayer == nil")
		return
	}
	if packet.Layers() == nil {
		log.Println("Layers == nil")
		return
	}
	// Extract TCP layer

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// Extract IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return
	}

	// Get TCP payload
	payload := tcp.Payload
	if len(payload) == 0 {
		return
	}

	// Construct server identifier
	srcAddr := fmt.Sprintf("%s:%d", ip.SrcIP, tcp.SrcPort)
	revAddr := fmt.Sprintf("%s:%d", ip.DstIP, tcp.DstPort)
	srcServer := fmt.Sprintf("%s:%d -> %s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	revServer := fmt.Sprintf("%s:%d -> %s:%d", ip.DstIP, tcp.DstPort, ip.SrcIP, tcp.SrcPort)

	cd.tcpMutex.Lock()
	defer cd.tcpMutex.Unlock()
	now := time.Now()

	// Check idle timeout
	if cd.currentServer != "" {
		if cd.currentServer == srcServer || cd.currentServer == revServer {
			cd.lastAnyPacketAt = now
		}
		// Timeout without recognizing data
		if cd.lastAnyPacketAt != (time.Time{}) && now.Sub(cd.lastAnyPacketAt) > cd.idleTimeout {
			cd.forceReconnect("idle timeout")
		}
	}
	// Server recognition logic
	if cd.currentServer != srcServer && cd.currentServer != revServer {
		findGameServer := false
		// Try to recognize server through small packet
		if len(payload) > 10 && payload[4] == 0 {
			data := payload[10:]
			if len(data) >= 4 { // Ensure at least 4 bytes available
				payloadMs := bytes.NewBuffer(data)
				for payloadMs.Len() >= 4 {
					var lenBuf [4]byte
					n, err := payloadMs.Read(lenBuf[:])
					if err != nil || n != 4 {
						break
					}

					msgLen := binary.BigEndian.Uint32(lenBuf[:])
					// Stricter length check
					if msgLen < 4 || msgLen > uint32(payloadMs.Len()) || msgLen > 0x0FFFFFFF {
						break
					}

					// Ensure enough data available
					if uint32(payloadMs.Len()) < msgLen-4 {
						break
					}

					tmp := make([]byte, msgLen-4)
					n, err = payloadMs.Read(tmp)
					if err != nil || uint32(n) != msgLen-4 {
						break
					}

					// Check server signature - enhanced boundary check
					sigLen := len(cd.serverSignature)
					if len(tmp) < 5+sigLen {
						break
					}
					if !bytes.Equal(tmp[5:5+sigLen], cd.serverSignature) {
						break
					}
					if cd.currentServer != srcServer {
						cd.currentServer = srcServer
						cd.clearTcpCache()
						cd.tcpNextSeq = tcp.Seq + uint32(len(payload))
						global.ClearAllData()
						log.Println("Recognized game server: ", srcAddr)
						findGameServer = true
						break
					}
				}
			}
		}

		// Try to recognize server through login response packet
		if len(payload) == 0x62 {
			if bytes.Equal(payload[0:10], cd.loginReturnSignature[0:10]) &&
				bytes.Equal(payload[14:20], cd.loginReturnSignature[14:20]) {
				// Set new game server identifier
				cd.currentServer = srcServer
				cd.clearTcpCache()
				cd.tcpNextSeq = tcp.Seq + uint32(len(payload))
				global.ClearAllData()
				log.Println("Recognized game server: ", srcAddr)
				findGameServer = true
			}
		}
		if len(payload) >= 6 {
			if payload[4] == 0 && payload[5] == 5 {
				data := payload[10:]
				if len(data) >= 4 { // Ensure at least 4 bytes available
					reader := bytes.NewReader(data)
					for {
						lenBuf := make([]byte, 4)
						n, err := reader.Read(lenBuf)
						if err != nil || n != 4 {
							break
						}
						length := binary.BigEndian.Uint32(lenBuf)
						if length < 4 || length > 0x0FFFFFFF {
							break
						}
						remaining := reader.Len()
						if int(length-4) > remaining {
							break
						}
						data1 := make([]byte, length-4)
						n, err = reader.Read(data1)
						if err != nil || uint32(n) != length-4 {
							break
						}
						// Check signature
						signature := []byte{0x00, 0x06, 0x26, 0xad, 0x66, 0x00}
						sigLen := len(signature)
						if len(data1) < 5+sigLen {
							break
						}

						if !bytes.Equal(data1[5:5+sigLen], signature) {
							break
						}

						if cd.currentServer != revServer {
							global.ClearAllData()
							cd.currentServer = revServer
							cd.clearTcpCache()
							cd.tcpNextSeq = tcp.Ack
							log.Println("Recognized game server: ", revAddr)
							findGameServer = true
							break
						}
					}
				}
			}
		}
		if !findGameServer {
			//log.Println("Not a game server: ", srcServer)
			return
		}
	}
	if len(cd.currentServer) == 0 {
		//log.Println("Waiting to recognize game server")
		return
	}
	// TCP stream reassembly
	cd.reassembleTcpStream(tcp, payload, now)
}

// reassembleTcpStream TCP stream reassembly
func (cd *CapDevice) reassembleTcpStream(tcp *layers.TCP, payload []byte, now time.Time) {
	// Initialize sequence number
	if cd.tcpNextSeq == 0 {
		if len(payload) > 4 && binary.BigEndian.Uint32(payload) < 0x0fffff {
			cd.tcpNextSeq = tcp.Seq
		} else {
			// Cannot determine initial sequence number, use current packet's sequence number
			cd.tcpNextSeq = tcp.Seq
		}
	}
	// Cache TCP packet
	seqKey := tcp.Seq
	cd.tcpCache[seqKey] = make([]byte, len(payload))
	copy(cd.tcpCache[seqKey], payload)
	cd.tcpCacheTime[seqKey] = now

	// Periodically clean up expired cache
	cd.cleanupOldCache(now)

	// Sequentially concatenate data
	messageBuffer := bytes.NewBuffer(nil)
	currentSeq := cd.tcpNextSeq

	for {
		if data, exists := cd.tcpCache[currentSeq]; exists {
			messageBuffer.Write(data)
			delete(cd.tcpCache, currentSeq)
			delete(cd.tcpCacheTime, currentSeq)

			cd.tcpNextSeq = currentSeq + uint32(len(data))
			currentSeq = cd.tcpNextSeq
			cd.lastAnyPacketAt = now
		} else {
			break
		}
	}

	// Append to TCP stream
	if messageBuffer.Len() > 0 {
		cd.tcpStream.Write(messageBuffer.Bytes())
	}
	// Parse messages
	cd.parseMessages()
}

// parseMessages parses messages
func (cd *CapDevice) parseMessages() {
	// Save current data
	currentData := cd.tcpStream.Bytes()
	dataLen := len(currentData)
	offset := 0
	for offset < dataLen {
		// Check if enough bytes available to read length
		if offset+4 > dataLen {
			break
		}

		// Read packet length
		packetSize := binary.BigEndian.Uint32(currentData[offset : offset+4])
		if packetSize <= 4 || packetSize > 0x0FFFFF {
			break
		}

		// Check if complete packet available
		if offset+int(packetSize) > dataLen {
			break
		}

		// Extract complete packet
		messagePacket := make([]byte, packetSize)
		copy(messagePacket, currentData[offset:offset+int(packetSize)])

		// Process message
		cd.handleProcess(messagePacket)

		// Move offset
		offset += int(packetSize)
	}

	// Update stream, keep only unprocessed data
	if offset > 0 {
		remaining := currentData[offset:]
		cd.tcpStream.Reset()
		cd.tcpStream.Write(remaining)
	}
}

// handleProcess processes packets
func (cd *CapDevice) handleProcess(packets []byte) {
	if len(packets) < 4 {
		return // Packet too small
	}

	reader := NewByteReader(packets)
	for reader.Remaining() > 0 {
		// Read packet length
		packetSize, ok := reader.TryPeekUInt32BE()
		if !ok {
			break
		}
		// Stricter boundary check
		if packetSize < 6 || packetSize > uint32(reader.Remaining()) || packetSize > 0x0FFFFFFF {
			break
		}

		// Ensure packetSize won't cause integer overflow
		if int(packetSize) < 0 || int(packetSize) > reader.Remaining() {
			break
		}

		// Read complete packet
		packetData, err := reader.ReadBytes(int(packetSize))
		if err != nil {
			break
		}

		// Verify packet data integrity
		if len(packetData) < 6 {
			continue
		}

		packetReader := NewByteReader(packetData)
		sizeAgain, err := packetReader.ReadUInt32BE()
		if err != nil || sizeAgain != packetSize {
			continue
		}

		// Read message type
		packetType, err := packetReader.ReadUInt16BE()
		if err != nil {
			continue
		}

		isZstdCompressed := (packetType & 0x8000) != 0
		msgTypeId := packetType & 0x7FFF

		// Dispatch to corresponding handler
		//log.Println(fmt.Sprintf("msgTypeId=%d", msgTypeId))
		cd.dispatchMessage(msgTypeId, packetReader, isZstdCompressed)
	}
}

// dispatchMessage dispatches messages
func (cd *CapDevice) dispatchMessage(msgTypeId uint16, reader *ByteReader, isZstdCompressed bool) {
	switch msgTypeId {
	case 2: // NotifyMsg
		cd.processNotifyMsg(reader, isZstdCompressed)
	case 6: // FrameDown
		cd.processFrameDown(reader, isZstdCompressed)
	}
}

// processNotifyMsg processes Notify messages
func (cd *CapDevice) processNotifyMsg(reader *ByteReader, isZstdCompressed bool) {
	serviceUuid, err := reader.ReadUInt64BE()
	if err != nil {
		return
	}

	_, err = reader.ReadUInt32BE()
	if err != nil {
		return
	}

	methodId, err := reader.ReadUInt32BE()
	if err != nil {
		return
	}
	if serviceUuid != 0x0000000063335342 {
		return
	}

	msgPayload := reader.ReadRemaining()
	if isZstdCompressed {
		msgPayload = cd.decompressZstdIfNeeded(msgPayload)
	}

	cd.processNotifyMethod(methodId, msgPayload)
}

// processFrameDown processes FrameDown messages
func (cd *CapDevice) processFrameDown(reader *ByteReader, isZstdCompressed bool) {
	if _, err := reader.ReadUInt32BE(); err != nil {
		return
	}

	if reader.Remaining() == 0 {
		return
	}

	nestedPacket := reader.ReadRemaining()
	if isZstdCompressed {
		nestedPacket = cd.decompressZstdIfNeeded(nestedPacket)
	}

	cd.handleProcess(nestedPacket) // Recursively parse internal messages
}

// processNotifyMethod processes Notify methods
func (cd *CapDevice) processNotifyMethod(methodId uint32, payload []byte) {
	//log.Println(methodId)
	switch methodId {
	case 0x03: // Scene switch
		cd.processSyncSceneData(payload)
	case 0x00000006: // Sync nearby player entities
		cd.processSyncNearEntities(payload)
	case 0x00000015: // Sync player's complete container data
		cd.processSyncContainerData(payload)
	case 0x00000016: // Sync player's partial update
	case 0x0000002E: // Sync incremental damage received by player
		cd.processSyncToMeDeltaInfo(payload)
	case 0x0000002D: // Sync nearby incremental damage
		cd.processSyncNearDeltaInfo(payload)
	}
}

// decompressZstdIfNeeded ZSTD decompression
func (cd *CapDevice) decompressZstdIfNeeded(buffer []byte) []byte {
	if len(buffer) < 4 {
		return buffer
	}

	decoder, err := zstd.NewReader(bytes.NewReader(buffer))
	if err != nil {
		return buffer
	}
	defer decoder.Close()

	result, err := io.ReadAll(decoder)
	if err != nil {
		return buffer
	}

	return result
}

// forceReconnect forces reconnection
func (cd *CapDevice) forceReconnect(reason string) {
	log.Println("[PacketAnalyzer] Reconnect due to ", reason, time.Now().Format("15:04:05"))
	cd.resetCaptureState()
}
func (cd *CapDevice) forceResyncTo(seq uint32) {
	log.Println("[PacketAnalyzer] Resync to seq= ", seq)
	cd.tcpNextSeq = 0                     // Fix: reset to 0
	cd.tcpCache = make(map[uint32][]byte) // Fix: use uint32
	cd.tcpCacheTime = make(map[uint32]time.Time)
	cd.tcpStream.Reset()
}

// resetCaptureState resets capture state
func (cd *CapDevice) resetCaptureState() {
	cd.currentServer = "" // Clear current server
	cd.clearTcpCache()
}

// clearTcpCache clears TCP cache
func (cd *CapDevice) clearTcpCache() {
	cd.tcpNextSeq = 0 // Fix: reset to 0
	cd.tcpStream.Reset()

	cd.tcpCache = make(map[uint32][]byte) // Fix: use uint32
	cd.tcpCacheTime = make(map[uint32]time.Time)
}

// cleanupOldCache cleans up expired TCP cache to prevent memory leaks
func (cd *CapDevice) cleanupOldCache(now time.Time) {
	// Clean up every 100 packets to avoid frequent cleanup
	if len(cd.tcpCache) < 100 {
		return
	}

	// Clean up cache exceeding gapTimeout
	for seq, timestamp := range cd.tcpCacheTime {
		if now.Sub(timestamp) > cd.gapTimeout {
			delete(cd.tcpCache, seq)
			delete(cd.tcpCacheTime, seq)
		}
	}

	// If cache is still too large, clean up the oldest half
	if len(cd.tcpCache) > 1000 {
		count := 0
		for seq := range cd.tcpCache {
			if count >= 500 {
				break
			}
			delete(cd.tcpCache, seq)
			delete(cd.tcpCacheTime, seq)
			count++
		}
		log.Printf("TCP cache too large, cleaned up %d expired entries", count)
	}
}

func (cd *CapDevice) processSyncSceneData(payload []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("Failed to parse scene switch data", err)
		}
	}()
	// Unknown proto format, temporarily read bytes to parse scene name
	start := 43
	if start >= len(payload) {
		return
	}
	length := int(payload[42])
	if start+length > len(payload) {
		length = len(payload) - start
	}
	if start+length > len(payload) {
		return
	}
	text := string(payload[start : start+length])
	pattern := regexp.MustCompile("([\u4e00-\u9fa5]+)")
	name := pattern.FindString(text)
	if len(strings.Trim(name, " ")) > 0 {
		log.Println("Scene switch: ", name)
		global.UpdateScene(func(info *global.SceneInfo) {
			if info != nil && info.Scene != nil {
				info.Scene.Name = name
			}
		})
	} else {
		log.Println("Scene switch: Unknown scene name")
		global.UpdateScene(func(info *global.SceneInfo) {
			if info != nil && info.Scene != nil {
				info.Scene.Name = ""
			}
		})
	}
}

// processSyncNearEntities processes synchronization of nearby entities
func (cd *CapDevice) processSyncNearEntities(payload []byte) {
	var msg pb.SyncNearEntities
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println("Failed to parse proto", err.Error())
		return
	}
	// Disappeared monsters
	if msg.Disappear != nil && len(msg.Disappear) > 0 {
		for _, item := range msg.GetDisappear() {
			uuid := uint64(item.GetUuid())
			if uuid > 0 && isMonsterUUID(uuid) {
				entityId := uuid >> 16
				if item.GetDisappearType() == pb.EDisappearType_EDisappearDead {
					global.FindMonsterId(entityId, func(monster *global.Monster) {
						monster.Hp = 0
					})
				}
			}
		}
	}

	if msg.Appear == nil || len(msg.Appear) == 0 {
		return
	}
	// Existing monsters
	for _, item := range msg.GetAppear() {
		attrs := item.Attrs
		entityId := uint64(item.Uuid >> 16)
		switch item.EntityType {
		case pb.EEntityType_EntMonster:
			monsterAttr(entityId, attrs)
		}
	}
}
func monsterAttr(entityId uint64, attrs *pb.AttrCollection) {
	// Monster data
	global.FindMonsterId(entityId, func(monster *global.Monster) {
		for _, attr := range attrs.GetAttrs() {
			if attr.Id == nil || attr.RawData == nil {
				continue
			}
			switch attr.GetId() {
			case 0x01: // Name
				value, n := protowire.ConsumeString(attr.RawData)
				if n > 0 && len(value) > 0 {
					log.Println(fmt.Sprintf("Found monster: %s#%d", value, entityId))
					monster.Name = value
				}
			case 0x0A: // Monster template ID
				value, n := protowire.ConsumeVarint(attr.RawData)
				if n > 0 {
					monster.TemplateId = value
					if name, has := global.MonsterNames[value]; has {
						log.Println(fmt.Sprintf("Found monster: %s#%d", name, entityId))
						monster.Name = name
					}
				}
			case 0x2C2E: // Current HP
				value, n := protowire.ConsumeVarint(attr.RawData)
				if n == 0 || len(attr.RawData) == 0 {
					monster.Hp = 0
				} else {
					monster.Hp = value
				}
			case 0x2C38: // Maximum HP
				value, n := protowire.ConsumeVarint(attr.RawData)
				if n > 0 {
					monster.MaxHp = value
				}
			}
		}
	})
}

// processSyncContainerData processes synchronization of player's complete container data
func (cd *CapDevice) processSyncContainerData(payload []byte) {
	var msg pb.SyncContainerData
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println(len(payload), "Failed to parse SyncContainerData", err.Error())
		return
	}
	if msg.VData == nil {
		return
	}
	vdata := msg.VData
	global.UpdateScene(func(info *global.SceneInfo) {
		if info == nil {
			return
		}

		// Update player ID
		if vdata.CharId > 0 {
			if info.Player != nil {
				info.Player.Id = uint64(vdata.CharId)
			}
		}

		// Update player combat rating
		if vdata.CharBase != nil {
			if point := vdata.CharBase.GetFightPoint(); point > 0 {
				if info.Player != nil {
					info.Player.FightPoint = point
				}
			}
			if v := vdata.CharBase.GetName(); len(v) > 0 {
				if info.Player != nil {
					info.Player.Name = v
				}
			}
			if v := vdata.GetRoleLevel(); v != nil {
				if v.Level > 0 && info.Player != nil {
					info.Player.Level = v.Level
				}
			}
		}

		// Update player HP
		if vdata.Attr != nil {
			if info.Player != nil {
				info.Player.Hp = vdata.Attr.GetCurHp()
				if v := vdata.Attr.GetMaxHp(); v > 0 {
					info.Player.MaxHp = v
				}
			}
		}

		if vdata.SceneData != nil {
			// Update scene data
			mapId := vdata.SceneData.GetMapId()   // Scene map ID
			lineId := vdata.SceneData.GetLineId() // Scene line/server ID
			// Update scene info
			if info.Scene != nil {
				// Receive line data first, then receive coordinate data
				if info.Scene.MapId != mapId {
					// Clear coordinates
					if info.Player != nil {
						info.Player.Pos = nil
					}
				}
				info.Scene.MapId = mapId
				info.Scene.LineId = lineId
			}
		}
	})
}

// processSyncToMeDeltaInfo processes synchronization of player's incremental damage
func (cd *CapDevice) processSyncToMeDeltaInfo(payload []byte) {
	var msg pb.SyncToMeDeltaInfo
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println("Failed to parse SyncToMeDeltaInfo", err.Error())
		return
	}
	info := msg.DeltaInfo
	if info.Uuid == nil {
		return
	}
	if info.BaseDelta == nil {
		return
	}
	baseDelta := info.GetBaseDelta()
	if info.Uuid != nil && cd.userUid != uint64(info.GetUuid()) {
		cd.userUid = uint64(info.GetUuid())
		log.Println(fmt.Sprintf("Obtained current player UUID: %d UID: %d", cd.userUid, cd.userUid>>16))
		global.UpdateScene(func(sceneInfo *global.SceneInfo) {
			if sceneInfo != nil && sceneInfo.Player != nil {
				sceneInfo.Player.Id = cd.userUid >> 16
			}
		})
	}
	// Get player's other information
	if baseDelta.Attrs != nil && baseDelta.Attrs.Attrs != nil && len(baseDelta.Attrs.Attrs) > 0 {
		for _, attr := range baseDelta.Attrs.GetAttrs() {
			switch attr.GetId() {
			case 53: // Parse coordinate data
				var posMsg pb.Vector3
				if err := proto.Unmarshal(attr.GetRawData(), &posMsg); err != nil {
					log.Println("Failed to parse coordinate data: ", err.Error())
					continue
				}
				global.UpdateScene(func(sceneInfo *global.SceneInfo) {
					if sceneInfo != nil && sceneInfo.Player != nil {
						//log.Println("Current coordinates:", posMsg.GetX(), posMsg.GetY(), posMsg.GetZ())
						sceneInfo.Player.Pos = &global.Position{
							X: posMsg.GetX(),
							Y: posMsg.GetY(),
							Z: posMsg.GetZ(),
						}
					}
				})
			}
		}
	}
	// Synchronize other data
	ProcessAoiSyncDelta(baseDelta)
}

// processSyncNearDeltaInfo processes synchronization of nearby incremental damage
func (cd *CapDevice) processSyncNearDeltaInfo(payload []byte) {
	var msg pb.SyncNearDeltaInfo
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println("Failed to parse SyncNearDeltaInfo", err.Error())
		return
	}
	if msg.DeltaInfos == nil || len(msg.DeltaInfos) == 0 {
		return
	}

	for _, item := range msg.DeltaInfos {
		ProcessAoiSyncDelta(item)
	}
}
func ProcessAoiSyncDelta(data *pb.AoiSyncDelta) {
	if data == nil {
		return
	}
	var targetUuidRaw = uint64(data.GetUuid())
	if targetUuidRaw == 0 {
		return
	}
	var isTargetPlayer = isPlayerUUID(targetUuidRaw)
	var targetUuid = targetUuidRaw >> 16
	if data.Attrs == nil {
		return
	}
	var attrCollection = data.Attrs
	if attrCollection.Attrs != nil {
		if !isTargetPlayer {
			monsterAttr(targetUuid, attrCollection)
		}
	}

	// Skill damage
	if data.SkillEffects == nil {
		return
	}
	var skillEffects = data.GetSkillEffects()
	if skillEffects.Damages == nil {
		return
	}
	for _, item := range skillEffects.Damages {
		if item.OwnerId == nil {
			continue
		}
		attackerUuid := uint64(item.GetTopSummonerId() | item.GetAttackerUuid())
		if attackerUuid == 0 {
			continue
		}
		isAttackerPlayer := isPlayerUUID(attackerUuid) // Whether damage source is a player
		attackerUuid = attackerUuid >> 16

		isDead := item.GetIsDead()                      // Whether dead
		isHeal := item.GetType() == pb.EDamageType_Heal // Whether heal

		if !isTargetPlayer { // Non-player target
			if !isHeal {
				if isAttackerPlayer {
					global.FindMonsterId(targetUuid, func(monster *global.Monster) {
						if monster.AttackPlayers == nil {
							monster.AttackPlayers = make(map[uint64]*global.AttackPlayer)
						}
						player, has := monster.AttackPlayers[attackerUuid]
						if !has {
							player = &global.AttackPlayer{
								LastAttackTime: time.Now().Unix(),
							}
						} else {
							player.LastAttackTime = time.Now().Unix()
						}
						monster.AttackPlayers[attackerUuid] = player
					})
				}
			}
			// Update monster coordinates
			if item.DamagePos != nil {
				global.FindMonsterId(targetUuid, func(monster *global.Monster) {
					monster.Pos = &global.Position{
						X: item.DamagePos.GetX(),
						Y: item.DamagePos.GetY(),
						Z: item.DamagePos.GetZ(),
					}
				})
			}
			if isDead { // Remove HP when monster dies
				global.FindMonsterId(targetUuid, func(monster *global.Monster) {
					monster.Hp = 0
				})
			}
		}

	}
}
func isPlayerUUID(uuid uint64) bool {
	return (uuid & 0xFFFF) == 640
}
func isMonsterUUID(uuid uint64) bool {
	return (uuid & 0xFFFF) == 64
}
