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

    def get_device(self, device_name: str) -> str:
        """
        Get network device by name

        Args:
            device_name: Device description or name

        Returns:
            Device name or interface object

        Raises:
            ValueError: If device not found
        """
        # Get all available devices
        devices = get_if_list()

        # Check if device exists
        if device_name in devices:
            # On Windows, we might need to get the actual interface object
            if WINDOWS and hasattr(conf, 'ifaces') and device_name in conf.ifaces:
                # Return the interface object for better compatibility on Windows
                return conf.ifaces[device_name]
            return device_name

        raise ValueError(f"Network adapter not found: {device_name}")

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
