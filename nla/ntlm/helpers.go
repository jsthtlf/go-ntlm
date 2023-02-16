//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"unicode/utf16"
)

// Concatenate two byte slices into a new slice
func concat(ar ...[]byte) []byte {
	return bytes.Join(ar, nil)
}

// Create a 0 initialized slice of bytes
func zeroBytes(length int) []byte {
	return make([]byte, length, length)
}

func randomBytes(length int) []byte {
	randombytes := make([]byte, length)
	_, err := rand.Read(randombytes)
	if err != nil {
	} // TODO: What to do with err here
	return randombytes
}

// Zero pad the input byte slice to the given size
// bytes - input byte slice
// offset - where to start taking the bytes from the input slice
// size - size of the output byte slize
func zeroPaddedBytes(bytes []byte, offset int, size int) []byte {
	newSlice := zeroBytes(size)
	for i := 0; i < size && i+offset < len(bytes); i++ {
		newSlice[i] = bytes[i+offset]
	}
	return newSlice
}

func MacsEqual(slice1, slice2 []byte) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := 0; i < len(slice1); i++ {
		// bytes between 4 and 7 (inclusive) contains random
		// data that should be ignored while comparing the
		// macs
		if (i < 4 || i > 7) && slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

func Utf16FromString(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	// TODO: I'm sure there is an easier way to do the conversion from utf16 to bytes
	result := zeroBytes(len(encoded) * 2)
	for i := 0; i < len(encoded); i++ {
		result[i*2] = byte(encoded[i])
		result[i*2+1] = byte(encoded[i] << 8)
	}
	return result
}

// Convert a UTF16 string to UTF8 string for Go usage
func utf16ToString(bytes []byte) string {
	var data []uint16

	// NOTE: This is definitely not the best way to do this, but when I tried using a buffer.Read I could not get it to work
	for offset := 0; offset < len(bytes); offset = offset + 2 {
		i := binary.LittleEndian.Uint16(bytes[offset : offset+2])
		data = append(data, i)
	}

	return string(utf16.Decode(data))
}

func uint32ToBytes(v uint32) []byte {
	bytes := make([]byte, 4)
	bytes[0] = byte(v & 0xff)
	bytes[1] = byte((v >> 8) & 0xff)
	bytes[2] = byte((v >> 16) & 0xff)
	bytes[3] = byte((v >> 24) & 0xff)
	return bytes
}

func readBytes(len int, r io.Reader) ([]byte, error) {
	b := make([]byte, len)
	length, err := io.ReadFull(r, b)
	return b[:length], err
}

func readByte(r io.Reader) (byte, error) {
	b, err := readBytes(1, r)
	return b[0], err
}

func readUInt8(r io.Reader) (uint8, error) {
	b, err := readBytes(1, r)
	return uint8(b[0]), err
}

func readUint16LE(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.LittleEndian.Uint16(b), nil
}

func readUint16BE(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.BigEndian.Uint16(b), nil
}

func readUInt32LE(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.LittleEndian.Uint32(b), nil
}

func readUInt32BE(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return 0, nil
	}
	return binary.BigEndian.Uint32(b), nil
}

func writeByte(data byte, w io.Writer) (int, error) {
	b := make([]byte, 1)
	b[0] = byte(data)
	return w.Write(b)
}

func writeBytes(data []byte, w io.Writer) (int, error) {
	return w.Write(data)
}

func writeUInt8(data uint8, w io.Writer) (int, error) {
	b := make([]byte, 1)
	b[0] = byte(data)
	return w.Write(b)
}

func writeUInt16BE(data uint16, w io.Writer) (int, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return w.Write(b)
}

func writeUInt16LE(data uint16, w io.Writer) (int, error) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, data)
	return w.Write(b)
}

func writeUInt32LE(data uint32, w io.Writer) (int, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, data)
	return w.Write(b)
}

func writeUInt32BE(data uint32, w io.Writer) (int, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, data)
	return w.Write(b)
}

func putUint16BE(data uint16) (uint8, uint8) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return uint8(b[0]), uint8(b[1])
}
