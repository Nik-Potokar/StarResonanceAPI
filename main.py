#!/usr/bin/env python3
"""
StarResonanceAPI - Main entry point
Packet capture and API for game data monitoring
"""
import argparse
import signal
import sys
import threading
import time
from typing import Optional

from scapy.all import get_if_list, WINDOWS, conf
from global_data import monster_names
from ncap import CapCore, get_active_network_cards
from api import run_api


def main():
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='StarResonanceAPI - Game Data API')
    parser.add_argument('--network', type=str, default='',
                        help='Network adapter description, use "auto" for automatic selection')
    parser.add_argument('--port', type=int, default=8989,
                        help='API port (default: 8989)')
    parser.add_argument('--expire', type=int, default=10,
                        help='Data expiration time in seconds (default: 10)')
    parser.add_argument('--autoCheckTime', type=int, default=3,
                        help='Time to wait for automatic network adapter detection in seconds (default: 3)')

    args = parser.parse_args()

    print("Github: https://github.com/balrogsxt/StarResonanceAPI")
    print("Python version by Claude Code")

    device_name = args.network

    # Get all network interfaces with descriptions
    try:
        devices = get_if_list()
        iface_descriptions = {}

        if WINDOWS:
            # On Windows, use scapy's conf.ifaces to get descriptions
            try:
                for iface_name in devices:
                    # Try to get description from scapy's interface configuration
                    if hasattr(conf, 'ifaces') and iface_name in conf.ifaces:
                        iface_obj = conf.ifaces[iface_name]
                        # Get the description/name attribute
                        desc = getattr(iface_obj, 'description', None) or getattr(iface_obj, 'name', iface_name)
                        iface_descriptions[iface_name] = desc
                    else:
                        iface_descriptions[iface_name] = iface_name
            except Exception as e:
                # If getting descriptions fails, just use interface names
                print(f"Warning: Unable to get network adapter descriptions: {e}")
                iface_descriptions = {iface: iface for iface in devices}
        else:
            # On non-Windows, use interface names
            iface_descriptions = {iface: iface for iface in devices}
    except Exception as e:
        print(f"Failed to get network adapters: {e}")
        sys.exit(1)

    if not devices:
        print("No network adapters found")
        sys.exit(1)

    # Auto-detect network interface
    if device_name == "auto":
        print("Automatically detecting active network adapter, please wait...")
        active = get_active_network_cards(args.autoCheckTime)
        if active:
            print(f"Automatically found suitable adapter: {active.desc}")
            print(f"Packets monitored: {active.packet_count}")
            print(f"Traffic monitored: {active.byte_count} bytes ({active.byte_count / 1024:.2f} KB)")
            device_name = active.name
        else:
            print("Unable to automatically find active network adapter")
            device_name = ""

    # Manual network interface selection
    if not device_name:
        print("\nUnable to automatically find active network adapter, please select manually:")
        print("Available network adapters:")
        for i, iface in enumerate(devices, 1):
            desc = iface_descriptions.get(iface, iface)
            # Show both description and name if they're different
            if desc != iface and len(desc) < 80:
                print(f"  {i}. {desc}")
            else:
                print(f"  {i}. {iface}")

        while True:
            try:
                choice = input("\nPlease select adapter number: ").strip()
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(devices):
                    device_name = devices[choice_idx]
                    selected_desc = iface_descriptions.get(device_name, device_name)
                    print(f"Selected: {selected_desc}")
                    break
                else:
                    print("Invalid selection, please try again")
            except (ValueError, KeyboardInterrupt):
                print("\nSelection error")
                sys.exit(1)

    if not device_name:
        print("No network adapter selected")
        sys.exit(1)

    # Load monster names
    try:
        monster_names.init_monster_names()
    except Exception as e:
        print(f"Failed to load monster name mappings: {e}")
        sys.exit(1)

    # Start API server in a separate thread
    api_thread = threading.Thread(
        target=run_api,
        args=(args.port, args.expire),
        daemon=True
    )
    api_thread.start()

    # Start packet capture in a separate thread
    def start_capture():
        try:
            cap_core = CapCore()
            cap_core.start(device_name)
        except Exception as e:
            print(f"Failed to start packet capture: {e}")
            sys.exit(1)

    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()

    # Setup signal handler for clean shutdown
    def signal_handler(sig, frame):
        print("\nShutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("Program started, press Ctrl+C to exit")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == '__main__':
    main()
