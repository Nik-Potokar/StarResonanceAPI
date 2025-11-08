"""
Packet capture core
"""
from scapy.all import conf, get_if_list, WINDOWS
from .cap_device import CapDevice


class CapCore:
    """Packet capture core class"""

    def __init__(self):
        """Initialize capture core"""
        pass

    def get_device(self, device_name: str):
        """
        Get network device by name

        Args:
            device_name: Device description or name

        Returns:
            Device name or network name suitable for sniffing

        Raises:
            ValueError: If device not found
        """
        # Get all available devices
        devices = get_if_list()

        # Check if device exists
        if device_name not in devices:
            raise ValueError(f"Network adapter not found: {device_name}")

        # On Windows, convert GUID to network name format if needed
        if WINDOWS:
            # If it's a GUID like {XXXXXXXX-...}, convert to \Device\NPF_{GUID}
            if device_name.startswith('{') and device_name.endswith('}'):
                network_name = f"\\Device\\NPF_{device_name}"
                return network_name
            # If it already starts with \Device\NPF_, use as-is
            elif device_name.startswith('\\Device\\NPF_'):
                return device_name

        return device_name

    def start(self, device_name: str):
        """
        Start packet capture

        Args:
            device_name: Device to capture from

        Raises:
            ValueError: If device not found
        """
        device = self.get_device(device_name)
        # Pass both the device object/name and the original name for display
        cap_device = CapDevice(device, device_name)
        cap_device.start()
