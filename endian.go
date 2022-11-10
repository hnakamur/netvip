package netvip

import (
	"encoding/binary"
)

func htons(i uint16) uint16 {
	// Store as big endian, retrieve as native endian.
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(i))
	return nativeEndian.Uint16(b[:])
}
