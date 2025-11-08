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

from scapy.all import get_if_list, WINDOWS
from global_data import monster_names as monster_names_module
from ncap import CapCore, get_active_network_cards
from api import run_api

# Try to import Windows-specific interface functions
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    try:
        from scapy.all import get_windows_if_list
    except ImportError:
        get_windows_if_list = None


def main():
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='StarResonanceAPI - Game Data API')
    parser.add_argument('--network', type=str, default='',
                        help='请输入网卡描述完整名称,auto为自动选择')
    parser.add_argument('--port', type=int, default=8989,
                        help='默认API端口')
    parser.add_argument('--expire', type=int, default=10,
                        help='数据过期时间(秒),默认10s')
    parser.add_argument('--autoCheckTime', type=int, default=3,
                        help='自动检查活动网卡时间(秒)')

    args = parser.parse_args()

    print("Github: https://github.com/balrogsxt/StarResonanceAPI")
    print("Python version by Claude Code")

    device_name = args.network

    # Get all network interfaces with descriptions
    try:
        devices = get_if_list()
        iface_descriptions = {}

        if WINDOWS and get_windows_if_list is not None:
            # On Windows, try to get interface descriptions
            try:
                win_ifaces = get_windows_if_list()
                for iface in win_ifaces:
                    iface_descriptions[iface['name']] = iface.get('description', iface['name'])
            except Exception as e:
                # If getting descriptions fails, just use interface names
                print(f"警告: 无法获取网卡描述信息: {e}")
                iface_descriptions = {iface: iface for iface in devices}
        else:
            # On non-Windows or if get_windows_if_list not available, use interface names
            iface_descriptions = {iface: iface for iface in devices}
    except Exception as e:
        print(f"获取网卡失败: {e}")
        sys.exit(1)

    if not devices:
        print("未找到任何网卡")
        sys.exit(1)

    # Auto-detect network interface
    if device_name == "auto":
        print("正在自动查找活动网卡,请稍等...")
        active = get_active_network_cards(args.autoCheckTime)
        if active:
            print(f"已自动找到合适的网卡: {active.desc}")
            print(f"监听数据包数量: {active.packet_count}")
            print(f"监听数据包流量: {active.byte_count} 字节 ({active.byte_count / 1024:.2f} KB)")
            device_name = active.name
        else:
            print("无法自动找到活动网卡")
            device_name = ""

    # Manual network interface selection
    if not device_name:
        print("\n无法自动找到活动网卡,请手动选择活动网卡:")
        print("可用网卡列表:")
        for i, iface in enumerate(devices, 1):
            desc = iface_descriptions.get(iface, iface)
            # Show both description and name if they're different
            if desc != iface and len(desc) < 80:
                print(f"  {i}. {desc}")
            else:
                print(f"  {i}. {iface}")

        while True:
            try:
                choice = input("\n请选择网卡编号: ").strip()
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(devices):
                    device_name = devices[choice_idx]
                    selected_desc = iface_descriptions.get(device_name, device_name)
                    print(f"已选择: {selected_desc}")
                    break
                else:
                    print("无效的选择,请重新输入")
            except (ValueError, KeyboardInterrupt):
                print("\n选择操作错误")
                sys.exit(1)

    if not device_name:
        print("选择网卡为空")
        sys.exit(1)

    # Load monster names
    try:
        monster_names_module.init_monster_names()
    except Exception as e:
        print(f"加载怪物映射表失败: {e}")
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
            print(f"启动抓包失败: {e}")
            sys.exit(1)

    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()

    # Setup signal handler for clean shutdown
    def signal_handler(sig, frame):
        print("\n正在关闭程序...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("程序已启动，按 Ctrl+C 退出")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在关闭程序...")
        sys.exit(0)


if __name__ == '__main__':
    main()
