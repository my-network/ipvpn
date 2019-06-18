package vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	MagicMACOctet0 = 0x44
	MagicMACOctet1 = 0x58

	macSize = 6
)

var (
	byteOrder = binary.BigEndian
)

type Mac interface {
	String() string
	Bytes() []byte
	Get(idx int) byte
	GetFrom(idx int) []byte
	IsHomenet() bool
	IsBroadcast() bool
	GetPeerIntAlias() uint32

	IsMAC() bool
}

func GenerateHomenetMAC(peerIntAlias uint32) (r mac) {
	r[0] = MagicMACOctet0 | 0x02
	r[1] = MagicMACOctet1
	fatalIf(binary.Write(&r, byteOrder, peerIntAlias))
	return
}

type mac [macSize]byte

func (mac *mac) Write(p []byte) (n int, err error) {
	for n = 0; n < len(p); n++ {
		mac[2+n] = p[n]
	}
	return
}

func (mac mac) IsMAC() bool {
	return true
}

func (mac mac) Bytes() []byte {
	return mac[:]
}

func (mac mac) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5],
	)
}
func (mac mac) Get(idx int) byte {
	return mac[idx]
}
func (mac mac) GetFrom(idx int) []byte {
	return mac[idx:]
}
func (mac mac) IsHomenet() bool {
	return mac[0] == MagicMACOctet0|0x02 && mac[1] == MagicMACOctet1
}
func (mac mac) IsBroadcast() bool {
	for i := 0; i < macSize; i++ {
		if mac[i] != 0xff {
			return false
		}
	}
	return true
}
func (mac mac) GetPeerIntAlias() (result uint32) {
	intAliasBytes := mac[2:]
	fatalIf(binary.Read(bytes.NewReader(intAliasBytes), binary.LittleEndian, &result))
	return
}

type macSlice []byte

func (mac macSlice) IsMAC() bool {
	return true
}

func (mac macSlice) Bytes() []byte {
	return mac
}

func (mac macSlice) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5],
	)
}

func (mac macSlice) Get(idx int) byte {
	return mac[idx]
}
func (mac macSlice) GetFrom(idx int) []byte {
	return mac[idx:]
}

func (mac macSlice) IsHomenet() bool {
	return mac[0] == MagicMACOctet0|0x02 && mac[1] == MagicMACOctet1
}
func (mac macSlice) IsBroadcast() bool {
	for i := 0; i < macSize; i++ {
		if mac[i] != 0xff {
			return false
		}
	}
	return true
}
func (mac macSlice) GetPeerIntAlias() (result uint32) {
	intAliasBytes := mac[2:]
	fatalIf(binary.Read(bytes.NewReader(intAliasBytes), byteOrder, &result))
	return
}
