"""
Byte reader utility for parsing binary data with big-endian byte order
"""
import struct
from typing import Tuple, Optional


class ByteReader:
    """Binary data reader with big-endian support"""

    def __init__(self, buffer: bytes, offset: int = 0):
        """
        Initialize byte reader

        Args:
            buffer: Byte buffer to read from
            offset: Starting offset
        """
        self.buffer = buffer
        self.offset = offset

    def remaining(self) -> int:
        """Get remaining bytes count"""
        return len(self.buffer) - self.offset

    def try_peek_uint32_be(self) -> Tuple[int, bool]:
        """
        Try to peek a 32-bit unsigned integer (big-endian) without moving offset

        Returns:
            Tuple of (value, success)
        """
        if self.remaining() < 4:
            return 0, False

        value = struct.unpack('>I', self.buffer[self.offset:self.offset + 4])[0]
        return value, True

    def read_uint64_be(self) -> int:
        """Read 64-bit unsigned integer (big-endian)"""
        if self.remaining() < 8:
            raise EOFError("Not enough bytes to read uint64")

        value = struct.unpack('>Q', self.buffer[self.offset:self.offset + 8])[0]
        self.offset += 8
        return value

    def peek_uint64_be(self) -> int:
        """Peek 64-bit unsigned integer (big-endian) without moving offset"""
        if self.remaining() < 8:
            raise EOFError("Not enough bytes to peek uint64")

        return struct.unpack('>Q', self.buffer[self.offset:self.offset + 8])[0]

    def read_uint32_be(self) -> int:
        """Read 32-bit unsigned integer (big-endian)"""
        if self.remaining() < 4:
            raise EOFError("Not enough bytes to read uint32")

        value = struct.unpack('>I', self.buffer[self.offset:self.offset + 4])[0]
        self.offset += 4
        return value

    def peek_uint32_be(self) -> int:
        """Peek 32-bit unsigned integer (big-endian) without moving offset"""
        if self.remaining() < 4:
            raise EOFError("Not enough bytes to peek uint32")

        return struct.unpack('>I', self.buffer[self.offset:self.offset + 4])[0]

    def read_uint16_be(self) -> int:
        """Read 16-bit unsigned integer (big-endian)"""
        if self.remaining() < 2:
            raise EOFError("Not enough bytes to read uint16")

        value = struct.unpack('>H', self.buffer[self.offset:self.offset + 2])[0]
        self.offset += 2
        return value

    def peek_uint16_be(self) -> int:
        """Peek 16-bit unsigned integer (big-endian) without moving offset"""
        if self.remaining() < 2:
            raise EOFError("Not enough bytes to peek uint16")

        return struct.unpack('>H', self.buffer[self.offset:self.offset + 2])[0]

    def read_bytes(self, length: int) -> bytes:
        """
        Read specified number of bytes

        Args:
            length: Number of bytes to read

        Returns:
            Bytes read
        """
        if length < 0 or self.remaining() < length:
            raise EOFError(f"Not enough bytes to read {length} bytes")

        result = self.buffer[self.offset:self.offset + length]
        self.offset += length
        return result

    def peek_bytes(self, length: int) -> bytes:
        """
        Peek specified number of bytes without moving offset

        Args:
            length: Number of bytes to peek

        Returns:
            Bytes peeked
        """
        if length < 0 or self.remaining() < length:
            raise EOFError(f"Not enough bytes to peek {length} bytes")

        return self.buffer[self.offset:self.offset + length]

    def read_remaining(self) -> bytes:
        """Read all remaining bytes"""
        remaining = self.remaining()
        if remaining == 0:
            return b''

        result = self.buffer[self.offset:]
        self.offset = len(self.buffer)
        return result
