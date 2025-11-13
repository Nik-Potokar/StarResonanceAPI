package ncap

import (
	"encoding/binary"
	"io"
)

// ByteReader byte reader for handling big-endian data
type ByteReader struct {
	buffer []byte
	offset int
}

// NewByteReader creates a new byte reader
func NewByteReader(buffer []byte, offset ...int) *ByteReader {
	off := 0
	if len(offset) > 0 {
		off = offset[0]
	}
	return &ByteReader{
		buffer: buffer,
		offset: off,
	}
}

// Remaining returns remaining readable bytes
func (br *ByteReader) Remaining() int {
	return len(br.buffer) - br.offset
}

// TryPeekUInt32BE tries to read big-endian 32-bit unsigned integer (without moving offset)
func (br *ByteReader) TryPeekUInt32BE() (uint32, bool) {
	if br.Remaining() < 4 {
		return 0, false
	}

	value := binary.BigEndian.Uint32(br.buffer[br.offset:])
	return value, true
}

// ReadUInt64BE reads big-endian 64-bit unsigned integer
func (br *ByteReader) ReadUInt64BE() (uint64, error) {
	if br.Remaining() < 8 {
		return 0, io.EOF
	}

	value := binary.BigEndian.Uint64(br.buffer[br.offset:])
	br.offset += 8
	return value, nil
}

// PeekUInt64BE peeks big-endian 64-bit unsigned integer (without moving offset)
func (br *ByteReader) PeekUInt64BE() (uint64, error) {
	if br.Remaining() < 8 {
		return 0, io.EOF
	}

	return binary.BigEndian.Uint64(br.buffer[br.offset:]), nil
}

// ReadUInt32BE reads big-endian 32-bit unsigned integer
func (br *ByteReader) ReadUInt32BE() (uint32, error) {
	if br.Remaining() < 4 {
		return 0, io.EOF
	}

	value := binary.BigEndian.Uint32(br.buffer[br.offset:])
	br.offset += 4
	return value, nil
}

// PeekUInt32BE peeks big-endian 32-bit unsigned integer (without moving offset)
func (br *ByteReader) PeekUInt32BE() (uint32, error) {
	if br.Remaining() < 4 {
		return 0, io.EOF
	}

	return binary.BigEndian.Uint32(br.buffer[br.offset:]), nil
}

// ReadUInt16BE reads big-endian 16-bit unsigned integer
func (br *ByteReader) ReadUInt16BE() (uint16, error) {
	if br.Remaining() < 2 {
		return 0, io.EOF
	}

	value := binary.BigEndian.Uint16(br.buffer[br.offset:])
	br.offset += 2
	return value, nil
}

// PeekUInt16BE peeks big-endian 16-bit unsigned integer (without moving offset)
func (br *ByteReader) PeekUInt16BE() (uint16, error) {
	if br.Remaining() < 2 {
		return 0, io.EOF
	}

	return binary.BigEndian.Uint16(br.buffer[br.offset:]), nil
}

// ReadBytes reads specified length of bytes
func (br *ByteReader) ReadBytes(length int) ([]byte, error) {
	if length < 0 || br.Remaining() < length {
		return nil, io.EOF
	}

	result := make([]byte, length)
	copy(result, br.buffer[br.offset:br.offset+length])
	br.offset += length
	return result, nil
}

// PeekBytes peeks specified length of bytes (without moving offset)
func (br *ByteReader) PeekBytes(length int) ([]byte, error) {
	if length < 0 || br.Remaining() < length {
		return nil, io.EOF
	}

	result := make([]byte, length)
	copy(result, br.buffer[br.offset:br.offset+length])
	return result, nil
}

// ReadRemaining reads all remaining bytes
func (br *ByteReader) ReadRemaining() []byte {
	remaining := br.Remaining()
	if remaining == 0 {
		return []byte{}
	}

	result := make([]byte, remaining)
	copy(result, br.buffer[br.offset:])
	br.offset = len(br.buffer)
	return result
}
