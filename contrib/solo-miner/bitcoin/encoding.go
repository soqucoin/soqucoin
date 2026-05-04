package bitcoin

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"
)

func doubleSha256Bytes(input []byte) [32]byte {
	sum := sha256.Sum256(input)
	sum = sha256.Sum256(sum[:])
	return sum
}

func varUint(value uint) string {
	var buffer []byte
	if value <= 252 {
		buffer = []byte{byte(value)}
	} else if value > 0xfd && value <= 0xffff {
		buffer = make([]byte, 2)
		binary.LittleEndian.PutUint16(buffer, uint16(value))
		buffer = append([]byte{0xfd}, buffer...)
	} else if value > 0xffff && value <= 0xffffffff {
		buffer = make([]byte, 4)
		binary.LittleEndian.PutUint32(buffer, uint32(value))
		buffer = append([]byte{0xfe}, buffer...)
	} else if value > 0xffffffff && value <= 0xffffffffffffffff {
		buffer = make([]byte, 8)
		binary.LittleEndian.PutUint64(buffer, uint64(value))
		buffer = append([]byte{0xff}, buffer...)
	} else {
		panic("Too large to stream")
	}

	return hex.EncodeToString(buffer)
}

func varUint64(value uint64) string {
	eightByteBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(eightByteBuffer, value)
	cleaned := removeInsignificantBytesLittleEndian(eightByteBuffer)
	return hex.EncodeToString(cleaned)
}

func fourLittleEndianBytes(value interface{}) []byte {
	fourByteBuffer := make([]byte, 4)
	switch binaryValue := value.(type) {
	case int:
		binary.LittleEndian.PutUint32(fourByteBuffer, uint32(binaryValue))
	case int16:
		binary.LittleEndian.PutUint32(fourByteBuffer, uint32(binaryValue))
	case int32:
		binary.LittleEndian.PutUint32(fourByteBuffer, uint32(binaryValue))
	case uint:
		binary.LittleEndian.PutUint32(fourByteBuffer, uint32(binaryValue))
	case uint16:
		binary.LittleEndian.PutUint32(fourByteBuffer, uint32(binaryValue))
	case float32:
		binary.LittleEndian.PutUint32(fourByteBuffer, uint32(binaryValue))
	case uint32:
		binary.LittleEndian.PutUint32(fourByteBuffer, binaryValue)
	default:
		log.Fatalln("Unable to write 4 byte stream: " + value.(string))
	}

	return fourByteBuffer
}

func eightLittleEndianBytes(value interface{}) []byte {
	eightByteBuffer := make([]byte, 8)
	switch binaryValue := value.(type) {
	case int:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case int16:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case int32:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case int64:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case uint:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case uint16:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case uint32:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case uint64:
		binary.LittleEndian.PutUint64(eightByteBuffer, binaryValue)
	case float32:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	case float64:
		binary.LittleEndian.PutUint64(eightByteBuffer, uint64(binaryValue))
	default:
		log.Fatalln("Unable to write 8 byte stream: " + value.(string))
	}

	return eightByteBuffer
}

func removeInsignificantBytesLittleEndian(input []byte) []byte {
	// Trim trailing zero bytes (little-endian: trailing = most significant)
	lastNonZero := len(input) - 1
	for lastNonZero > 0 && input[lastNonZero] == 0 {
		lastNonZero--
	}
	cleaned := input[:lastNonZero+1]

	// BIP34 fix: if the MSB of the last byte is set (0x80), the value
	// would be interpreted as negative in Bitcoin Script. Append a 0x00
	// byte to keep it positive. This is required for heights >= 128.
	if len(cleaned) > 0 && cleaned[len(cleaned)-1]&0x80 != 0 {
		cleaned = append(cleaned, 0x00)
	}

	return cleaned
}

func bytesWithLengthHeader(bytes []byte) []byte {
	lenHeader := []byte{byte(len(bytes))}
	return append(lenHeader, bytes...)
}

func reverse(b []byte) []byte {
	r := make([]byte, len(b))
	length := len(b)
	lengthMinusOne := (length - 1)
	for index := range b {
		r[lengthMinusOne-index] = b[index]
	}
	return r
}

func reverseHexBytes(hex string) (string, error) {
	if len(hex)%2 != 0 {
		return "", errors.New("string must be divisible by 2 to be a byte string")
	}
	o := ""
	l := len(hex)
	for i := l; i > 0; i = i - 2 {
		o = o + hex[i-2:i]
	}
	return o, nil
}

func reverseHex4Bytes(hex string) (string, error) {
	if len(hex)%8 != 0 {
		return "", errors.New("string must be divisible by 8 to represent 4 byte array")
	}

	var o string

	for l, i := len(hex), 0; i < l/8; i++ {
		o = o + hex[l-8*(i+1):(l-(8*i))]
	}

	return o, nil
}
