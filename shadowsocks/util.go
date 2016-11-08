package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

func PrintVersion() {
	const version = "1.1.5"
	fmt.Println("shadowsocks-go version", version)
}

func IsFileExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err == nil {
		if stat.Mode()&os.ModeType == 0 {
			return true, nil
		}
		return false, errors.New(path + " exists but is not regular file")
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func HmacSha1(key []byte, data []byte) []byte {
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(data)
	return hmacSha1.Sum(nil)[:10]
}

func otaConnectAuth(iv, key, data []byte) []byte {
	return append(data, HmacSha1(append(iv, key...), data)...)
}

func otaReqChunkAuth(iv []byte, chunkId uint32, data []byte) []byte {
	nb := make([]byte, 2)
	binary.BigEndian.PutUint16(nb, uint16(len(data)))
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
	header := append(nb, HmacSha1(append(iv, chunkIdBytes...), data)...)
	return append(header, data...)
}

type ClosedFlag struct {
	flag bool
}

func (flag *ClosedFlag) SetClosed() {
	flag.flag = true
}

func (flag *ClosedFlag) IsClosed() bool {
	return flag.flag
}

// Normal request header:
// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port) + 10(hmac-sha1)
// Add command type:
// Defined command request length(3):
// command_header(1) + command_type(2).
// At now, command_header always be 0x80

var (

	// Least changing the orignal code, use error type to distingush if command.
	CommandSignal = errors.New("Command Type")

	CommandLength = 3

	// Command header 1 byte,
	// Response command, should also carry this header.
	CommandHeader = 0x08

	// Command type 2 byte, new only one command type
	// 0x0101 for check if the proxy sever alive,
	// BigEndian
	// return 0x0103 also, like 0x080103 if is aviable,
	// TODO: add more type to response.
	CheckAliveCmd = 0x0103
)
