package ncap

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

// CapCore packet capture core class
type CapCore struct{}

// NewCapCore creates a new packet capture core
func NewCapCore() *CapCore {
	return &CapCore{}
}

// GetDevice gets network device
func (cc *CapCore) GetDevice(deviceName string) (*pcap.Handle, error) {
	// Find all network devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to get network card list: %v", err)
	}

	// Find device with specified name
	for _, device := range devices {
		if device.Description == deviceName {
			// Open device
			handle, err := pcap.OpenLive(
				device.Name,
				1024*1024*10,
				true,
				pcap.BlockForever,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to open network card %s: %v", device.Name, err)
			}
			return handle, nil
		}
	}

	return nil, fmt.Errorf("network device does not exist: %s", deviceName)
}

// Start starts packet capture
func (cc *CapCore) Start(deviceName string) error {
	device, err := cc.GetDevice(deviceName)
	if err != nil {
		return fmt.Errorf("failed to get network card: %v", err)
	}
	capDevice := NewCapDevice(device, deviceName)
	return capDevice.Start()
}
