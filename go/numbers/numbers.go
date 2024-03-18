package numbers

import (
	"encoding/binary"

	t "github.com/christoffercarlsson/autograph/go/types"
)

func GetUint32(bytes *[]byte, offset int) uint32 {
	return binary.BigEndian.Uint32((*bytes)[offset : offset+4])
}

func SetUint32(bytes *[]byte, offset int, number uint32) {
	newBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(newBytes, number)
	for i := 0; i < 4; i += 1 {
		(*bytes)[i+int(offset)] = newBytes[i]
	}
}

func GetUint64(bytes *[]byte, offset int) uint64 {
	return binary.BigEndian.Uint64(*bytes)
}

func SetUint64(bytes *[]byte, offset int, number uint64) {
	newBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(newBytes, number)
	for i := 0; i < 8; i += 1 {
		(*bytes)[i+int(offset)] = newBytes[i]
	}
}

func ReadIndex(index t.Index) uint32 {
	indexSlice := index[:]
	return GetUint32(&indexSlice, 0)
}

func ReadSize(size t.Size) int {
	sizeSlice := size[:]
	return int(GetUint64(&sizeSlice, 0))
}

func SetSize(bytes *t.Size, size int) {
	bytesSlice := bytes[:]
	SetUint64(&bytesSlice, 0, uint64(size))
}
