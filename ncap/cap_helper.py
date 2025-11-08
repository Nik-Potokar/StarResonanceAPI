"""
Network interface helper functions
"""
import time
import threading
from typing import List, Optional
from dataclasses import dataclass
from scapy.all import conf, sniff, get_if_list


@dataclass
class InterfaceStats:
    """Network interface statistics"""
    name: str
    desc: str
    packet_count: int = 0
    byte_count: int = 0


def get_active_network_cards(auto_check_time: int = 3) -> Optional[InterfaceStats]:
    """
    Detect active network interface by monitoring traffic

    Args:
        auto_check_time: Time in seconds to monitor interfaces

    Returns:
        Most active interface or None
    """
    # Get all network interfaces
    interfaces = get_if_list()

    if not interfaces:
        print("No network adapters found")
        return None

    check_time = max(auto_check_time, 1)
    print(f"Starting to monitor all network adapter traffic, please wait {check_time} seconds")

    stats = {}
    done = threading.Event()

    # Start monitoring each interface
    threads = []
    for iface in interfaces:
        stats[iface] = InterfaceStats(name=iface, desc=iface)
        thread = threading.Thread(
            target=monitor_interface,
            args=(iface, stats[iface], done),
            daemon=True
        )
        thread.start()
        threads.append(thread)

    # Wait for monitoring period
    time.sleep(check_time)
    done.set()

    # Wait a bit for threads to finish
    time.sleep(0.1)

    # Find most active interface
    max_packets = 0
    max_bytes = 0
    active_interface = None

    for stat in stats.values():
        if stat.packet_count > max_packets or \
                (stat.packet_count == max_packets and stat.byte_count > max_bytes):
            max_packets = stat.packet_count
            max_bytes = stat.byte_count
            active_interface = stat

    if active_interface and active_interface.packet_count > 0:
        return active_interface
    else:
        return None


def monitor_interface(device_name: str, stats: InterfaceStats, done: threading.Event):
    """
    Monitor a single interface for traffic

    Args:
        device_name: Interface name
        stats: Statistics object to update
        done: Event to signal when to stop
    """
    def packet_handler(packet):
        if done.is_set():
            return True  # Stop sniffing
        stats.packet_count += 1
        stats.byte_count += len(packet)
        return False

    try:
        # Sniff packets on this interface
        sniff(
            iface=device_name,
            prn=packet_handler,
            store=False,
            timeout=1,
            stop_filter=lambda x: done.is_set()
        )
    except Exception as e:
        # Some interfaces might not be accessible, silently ignore
        pass
