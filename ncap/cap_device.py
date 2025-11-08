"""
Packet capture device with TCP reassembly and protocol parsing
"""
import time
import threading
import struct
import re
import zstandard as zstd
from typing import Dict, Optional
from io import BytesIO
from scapy.all import sniff, TCP, IP

from .byte_reader import ByteReader
from .queue import Queue
from global_data import cache, monster_names
import pb.messages as pb


class CapDevice:
    """Packet capture device with TCP stream reassembly"""

    def __init__(self, device: str, device_name: str):
        """
        Initialize capture device

        Args:
            device: Device interface name
            device_name: Device description
        """
        self.device_name = device_name
        self.device = device
        self.current_server = ""
        self.user_uid = 0

        # TCP reassembly
        self.tcp_mutex = threading.Lock()
        self.tcp_data_buffer = bytearray()
        self.tcp_cache_time: Dict[int, float] = {}
        self.tcp_cache: Dict[int, bytes] = {}
        self.tcp_stream = BytesIO()
        self.tcp_next_seq = 0
        self.last_any_packet_at = 0.0

        # Configuration
        self.idle_timeout = 10.0  # seconds
        self.gap_timeout = 2.0  # seconds

        # Server signatures
        self.server_signature = bytes([0x00, 0x63, 0x33, 0x53, 0x42, 0x00])
        self.login_return_signature = bytes([
            0x00, 0x00, 0x00, 0x62,
            0x00, 0x03,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x11, 0x45, 0x14,
            0x00, 0x00, 0x00, 0x00,
            0x0a, 0x4e, 0x08, 0x01, 0x22, 0x24,
        ])

        self.packet_queue = Queue()

    def start(self):
        """Start packet capture"""
        print(f"Starting network packet capture: {self.device_name}")

        # Start packet processing thread
        processing_thread = threading.Thread(target=self._process_queue, daemon=True)
        processing_thread.start()

        # Start capturing packets
        try:
            sniff(
                iface=self.device,
                filter="ip and tcp",
                prn=self._enqueue_packet,
                store=False
            )
        except Exception as e:
            print(f"数据包捕获错误: {e}")
            raise

    def _enqueue_packet(self, packet):
        """Enqueue packet for processing"""
        if packet:
            self.packet_queue.enqueue(packet)

    def _process_queue(self):
        """Process packets from queue"""
        while True:
            packet, ok = self.packet_queue.dequeue()
            if ok:
                self.handle_packet(packet)
            else:
                time.sleep(0.05)

    def handle_packet(self, packet):
        """Handle a single packet"""
        try:
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return

            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
            if not payload:
                return

            # Construct server identifiers
            src_addr = f"{ip_layer.src}:{tcp_layer.sport}"
            dst_addr = f"{ip_layer.dst}:{tcp_layer.dport}"
            src_server = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
            rev_server = f"{ip_layer.dst}:{tcp_layer.dport} -> {ip_layer.src}:{tcp_layer.sport}"

            with self.tcp_mutex:
                now = time.time()

                # Check idle timeout
                if self.current_server:
                    if self.current_server == src_server or self.current_server == rev_server:
                        self.last_any_packet_at = now

                    # Timeout check
                    if self.last_any_packet_at and (now - self.last_any_packet_at) > self.idle_timeout:
                        self.force_reconnect("idle timeout")

                # Server identification logic
                if self.current_server != src_server and self.current_server != rev_server:
                    find_game_server = False

                    # Try to identify server by small packet signature
                    if len(payload) > 10 and payload[4] == 0:
                        data = payload[10:]
                        if len(data) >= 4:
                            find_game_server = self._identify_by_signature(
                                data, src_server, src_addr, tcp_layer.seq, len(payload)
                            )

                    # Try to identify by login return packet
                    if not find_game_server and len(payload) == 0x62:
                        if (payload[0:10] == self.login_return_signature[0:10] and
                                payload[14:20] == self.login_return_signature[14:20]):
                            self.current_server = src_server
                            self.clear_tcp_cache()
                            self.tcp_next_seq = tcp_layer.seq + len(payload)
                            cache.clear_all_data()
                            print(f"Game server identified: {src_addr}")
                            find_game_server = True

                    # Check reverse direction
                    if not find_game_server and len(payload) >= 6:
                        if payload[4] == 0 and payload[5] == 5:
                            find_game_server = self._identify_reverse_server(
                                payload[10:], rev_server, dst_addr, tcp_layer.ack
                            )

                    if not find_game_server:
                        return

                if not self.current_server:
                    return

                # TCP stream reassembly
                self.reassemble_tcp_stream(tcp_layer, payload, now)

        except Exception as e:
            print(f"handlePacket Error: {e}")

    def _identify_by_signature(self, data: bytes, src_server: str,
                                src_addr: str, seq: int, payload_len: int) -> bool:
        """Identify server by packet signature"""
        reader = BytesIO(data)
        while True:
            len_buf = reader.read(4)
            if len(len_buf) != 4:
                break

            msg_len = struct.unpack('>I', len_buf)[0]
            if msg_len < 4 or msg_len > 0x0FFFFFFF:
                break

            remaining = len(data) - reader.tell()
            if msg_len - 4 > remaining:
                break

            tmp = reader.read(msg_len - 4)
            if len(tmp) != msg_len - 4:
                break

            # Check server signature
            sig_len = len(self.server_signature)
            if len(tmp) < 5 + sig_len:
                break

            if tmp[5:5 + sig_len] != self.server_signature:
                break

            if self.current_server != src_server:
                self.current_server = src_server
                self.clear_tcp_cache()
                self.tcp_next_seq = seq + payload_len
                cache.clear_all_data()
                print(f"Game server identified: {src_addr}")
                return True

        return False

    def _identify_reverse_server(self, data: bytes, rev_server: str,
                                  rev_addr: str, ack: int) -> bool:
        """Identify server in reverse direction"""
        if len(data) < 4:
            return False

        reader = BytesIO(data)
        while True:
            len_buf = reader.read(4)
            if len(len_buf) != 4:
                break

            length = struct.unpack('>I', len_buf)[0]
            if length < 4 or length > 0x0FFFFFFF:
                break

            remaining = len(data) - reader.tell()
            if length - 4 > remaining:
                break

            data1 = reader.read(length - 4)
            if len(data1) != length - 4:
                break

            # Check signature
            signature = bytes([0x00, 0x06, 0x26, 0xad, 0x66, 0x00])
            sig_len = len(signature)
            if len(data1) < 5 + sig_len:
                break

            if data1[5:5 + sig_len] != signature:
                break

            if self.current_server != rev_server:
                cache.clear_all_data()
                self.current_server = rev_server
                self.clear_tcp_cache()
                self.tcp_next_seq = ack
                print(f"Game server identified: {rev_addr}")
                return True

        return False

    def reassemble_tcp_stream(self, tcp: TCP, payload: bytes, now: float):
        """Reassemble TCP stream"""
        # Initialize sequence number
        if self.tcp_next_seq == 0:
            if len(payload) > 4:
                try:
                    first_int = struct.unpack('>I', payload[:4])[0]
                    if first_int < 0x0fffff:
                        self.tcp_next_seq = tcp.seq
                    else:
                        self.tcp_next_seq = tcp.seq
                except:
                    self.tcp_next_seq = tcp.seq
            else:
                self.tcp_next_seq = tcp.seq

        # Cache TCP packet
        seq_key = tcp.seq
        self.tcp_cache[seq_key] = bytes(payload)
        self.tcp_cache_time[seq_key] = now

        # Cleanup old cache
        self.cleanup_old_cache(now)

        # Sequentially concatenate data
        message_buffer = BytesIO()
        current_seq = self.tcp_next_seq

        while True:
            if current_seq in self.tcp_cache:
                data = self.tcp_cache[current_seq]
                message_buffer.write(data)
                del self.tcp_cache[current_seq]
                del self.tcp_cache_time[current_seq]

                self.tcp_next_seq = current_seq + len(data)
                current_seq = self.tcp_next_seq
                self.last_any_packet_at = now
            else:
                break

        # Append to TCP stream
        if message_buffer.tell() > 0:
            self.tcp_stream.write(message_buffer.getvalue())

        # Parse messages
        self.parse_messages()

    def parse_messages(self):
        """Parse messages from TCP stream"""
        current_data = self.tcp_stream.getvalue()
        data_len = len(current_data)
        offset = 0

        while offset < data_len:
            # Check if enough bytes for length
            if offset + 4 > data_len:
                break

            # Read packet size
            packet_size = struct.unpack('>I', current_data[offset:offset + 4])[0]
            if packet_size <= 4 or packet_size > 0x0FFFFF:
                break

            # Check if we have complete packet
            if offset + packet_size > data_len:
                break

            # Extract complete packet
            message_packet = current_data[offset:offset + packet_size]

            # Process message
            self.handle_process(message_packet)

            # Move offset
            offset += packet_size

        # Update stream with remaining data
        if offset > 0:
            remaining = current_data[offset:]
            self.tcp_stream = BytesIO()
            self.tcp_stream.write(remaining)

    def handle_process(self, packets: bytes):
        """Process data packet"""
        if len(packets) < 4:
            return

        reader = ByteReader(packets)
        while reader.remaining() > 0:
            # Read packet size
            packet_size, ok = reader.try_peek_uint32_be()
            if not ok:
                break

            # Boundary check
            if packet_size < 6 or packet_size > reader.remaining() or packet_size > 0x0FFFFFFF:
                break

            # Read complete packet
            try:
                packet_data = reader.read_bytes(packet_size)
            except:
                break

            # Validate packet
            if len(packet_data) < 6:
                continue

            packet_reader = ByteReader(packet_data)
            try:
                size_again = packet_reader.read_uint32_be()
                if size_again != packet_size:
                    continue
            except:
                continue

            # Read message type
            try:
                packet_type = packet_reader.read_uint16_be()
            except:
                continue

            is_zstd_compressed = (packet_type & 0x8000) != 0
            msg_type_id = packet_type & 0x7FFF

            # Dispatch to handler
            self.dispatch_message(msg_type_id, packet_reader, is_zstd_compressed)

    def dispatch_message(self, msg_type_id: int, reader: ByteReader, is_zstd_compressed: bool):
        """Dispatch message to appropriate handler"""
        if msg_type_id == 2:  # NotifyMsg
            self.process_notify_msg(reader, is_zstd_compressed)
        elif msg_type_id == 6:  # FrameDown
            self.process_frame_down(reader, is_zstd_compressed)

    def process_notify_msg(self, reader: ByteReader, is_zstd_compressed: bool):
        """Process Notify message"""
        try:
            service_uuid = reader.read_uint64_be()
            reader.read_uint32_be()  # Skip
            method_id = reader.read_uint32_be()

            if service_uuid != 0x0000000063335342:
                return

            msg_payload = reader.read_remaining()
            if is_zstd_compressed:
                msg_payload = self.decompress_zstd(msg_payload)

            self.process_notify_method(method_id, msg_payload)
        except:
            pass

    def process_frame_down(self, reader: ByteReader, is_zstd_compressed: bool):
        """Process FrameDown message"""
        try:
            reader.read_uint32_be()  # Skip

            if reader.remaining() == 0:
                return

            nested_packet = reader.read_remaining()
            if is_zstd_compressed:
                nested_packet = self.decompress_zstd(nested_packet)

            self.handle_process(nested_packet)
        except:
            pass

    def process_notify_method(self, method_id: int, payload: bytes):
        """Process Notify method"""
        if method_id == 0x03:  # Scene change
            self.process_sync_scene_data(payload)
        elif method_id == 0x00000006:  # Sync near entities
            self.process_sync_near_entities(payload)
        elif method_id == 0x00000015:  # Sync container data
            self.process_sync_container_data(payload)
        elif method_id == 0x0000002E:  # Sync to me delta
            self.process_sync_to_me_delta_info(payload)
        elif method_id == 0x0000002D:  # Sync near delta
            self.process_sync_near_delta_info(payload)

    def decompress_zstd(self, buffer: bytes) -> bytes:
        """Decompress ZSTD data"""
        if len(buffer) < 4:
            return buffer

        try:
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(buffer)
        except:
            return buffer

    def process_sync_scene_data(self, payload: bytes):
        """Process scene sync data"""
        try:
            # Unknown proto format, parse scene name from bytes
            start = 43
            if start >= len(payload):
                return

            length = int(payload[42])
            if start + length > len(payload):
                length = len(payload) - start

            if start + length > len(payload):
                return

            text = payload[start:start + length].decode('utf-8', errors='ignore')
            pattern = re.compile(r'([\u4e00-\u9fa5]+)')
            match = pattern.search(text)

            if match:
                name = match.group(1).strip()
                if name:
                    print(f"Scene changed: {name}")
                    cache.update_scene(lambda info: setattr(info.scene, 'name', name))
                else:
                    print("Scene changed: Unknown scene name")
                    cache.update_scene(lambda info: setattr(info.scene, 'name', ""))
        except Exception as e:
            print(f"Failed to parse scene change data: {e}")

    def process_sync_near_entities(self, payload: bytes):
        """Process sync near entities - simplified version"""
        # Note: Full protobuf parsing would require the complete .proto file
        # This is a placeholder for the actual implementation
        pass

    def process_sync_container_data(self, payload: bytes):
        """Process sync container data - simplified version"""
        # Note: Full protobuf parsing would require the complete .proto file
        pass

    def process_sync_to_me_delta_info(self, payload: bytes):
        """Process sync to me delta info - simplified version"""
        pass

    def process_sync_near_delta_info(self, payload: bytes):
        """Process sync near delta info - simplified version"""
        pass

    def force_reconnect(self, reason: str):
        """Force reconnect"""
        print(f"[PacketAnalyzer] Reconnect due to {reason} {time.strftime('%H:%M:%S')}")
        self.reset_capture_state()

    def reset_capture_state(self):
        """Reset capture state"""
        self.current_server = ""
        self.clear_tcp_cache()

    def clear_tcp_cache(self):
        """Clear TCP cache"""
        self.tcp_next_seq = 0
        self.tcp_stream = BytesIO()
        self.tcp_cache = {}
        self.tcp_cache_time = {}

    def cleanup_old_cache(self, now: float):
        """Cleanup old TCP cache to prevent memory leak"""
        if len(self.tcp_cache) < 100:
            return

        # Clean cache older than gap_timeout
        to_delete = []
        for seq, timestamp in self.tcp_cache_time.items():
            if now - timestamp > self.gap_timeout:
                to_delete.append(seq)

        for seq in to_delete:
            del self.tcp_cache[seq]
            del self.tcp_cache_time[seq]

        # If cache still too large, clean oldest half
        if len(self.tcp_cache) > 1000:
            count = 0
            for seq in list(self.tcp_cache.keys()):
                if count >= 500:
                    break
                del self.tcp_cache[seq]
                if seq in self.tcp_cache_time:
                    del self.tcp_cache_time[seq]
                count += 1
            print(f"TCP cache too large, cleaned {count} expired entries")


def is_player_uuid(uuid: int) -> bool:
    """Check if UUID is a player"""
    return (uuid & 0xFFFF) == 640


def is_monster_uuid(uuid: int) -> bool:
    """Check if UUID is a monster"""
    return (uuid & 0xFFFF) == 64
