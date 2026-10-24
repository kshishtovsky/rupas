//go:build windows

package windivert

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// AddressSize is sizeof(WINDIVERT_ADDRESS) for WinDivert 2.2 on 64-bit
// Windows: 8 (Timestamp) + 4 (bit-field unit) + 4 (Reserved2) + 64 (union).
const AddressSize = 80

// Address mirrors WINDIVERT_ADDRESS from the official WinDivert 2.2
// windivert.h, byte-exact for windows/amd64:
//
//	offset  size  C declaration
//	     0     8  INT64  Timestamp
//	     8     4  UINT32 bit-field: Layer:8, Event:8, Sniffed..UDPChecksum
//	                  (8 single bits), Reserved1:8
//	    12     4  UINT32 Reserved2
//	    16    64  union { WINDIVERT_DATA_NETWORK, _FLOW, _SOCKET,
//	                     _REFLECT, UINT8 Reserved3[64] }
//
// MSVC packs the Layer/Event/flags bit-field into one 32-bit unit, first
// declared bit = LSB. The unit is decomposed into explicit bytes so that
// unsafe.Sizeof(Address{}) == 80 and every field lands on the exact offset
// used by the DLL (verified live against the driver):
//
//	byte  8: Layer
//	byte  9: Event
//	byte 10: flag bits, Sniffed=1<<0, Outbound=1<<1, Loopback=1<<2,
//	         Impostor=1<<3, IPv6=1<<4, IPChecksum=1<<5, TCPChecksum=1<<6,
//	         UDPChecksum=1<<7
//	byte 11: Reserved1
type Address struct {
	Timestamp int64
	Layer     uint8
	Event     uint8
	flags     uint8
	Reserved1 uint8
	Reserved2 uint32
	Data      [64]byte // union storage; use Network()/Flow()/Socket()/Reflect()
}

// Flag bit positions inside the byte at offset 10 (LSB-first, per MSVC).
const (
	flagSniffed     = 1 << 0
	flagOutbound    = 1 << 1
	flagLoopback    = 1 << 2
	flagImpostor    = 1 << 3
	flagIPv6        = 1 << 4
	flagIPChecksum  = 1 << 5
	flagTCPChecksum = 1 << 6
	flagUDPChecksum = 1 << 7
)

func (a *Address) Sniffed() bool     { return a.flags&flagSniffed != 0 }
func (a *Address) Outbound() bool    { return a.flags&flagOutbound != 0 }
func (a *Address) Loopback() bool    { return a.flags&flagLoopback != 0 }
func (a *Address) Impostor() bool    { return a.flags&flagImpostor != 0 }
func (a *Address) IPv6() bool        { return a.flags&flagIPv6 != 0 }
func (a *Address) IPChecksum() bool  { return a.flags&flagIPChecksum != 0 }
func (a *Address) TCPChecksum() bool { return a.flags&flagTCPChecksum != 0 }
func (a *Address) UDPChecksum() bool { return a.flags&flagUDPChecksum != 0 }

// SetOutbound flips the direction bit (must be cleared when re-injecting a
// captured packet on the opposite direction).
func (a *Address) SetOutbound(v bool) { a.flags = setFlag(a.flags, flagOutbound, v) }

// SetIPChecksum / SetTCPChecksum / SetUDPChecksum invalidate the
// corresponding checksum-valid hints after in-place packet edits.
func (a *Address) SetIPChecksum(v bool)  { a.flags = setFlag(a.flags, flagIPChecksum, v) }
func (a *Address) SetTCPChecksum(v bool) { a.flags = setFlag(a.flags, flagTCPChecksum, v) }
func (a *Address) SetUDPChecksum(v bool) { a.flags = setFlag(a.flags, flagUDPChecksum, v) }

func setFlag(b, bit uint8, v bool) uint8 {
	if v {
		return b | bit
	}
	return b &^ bit
}

// NetworkData mirrors WINDIVERT_DATA_NETWORK (NETWORK/NETWORK_FORWARD layers).
type NetworkData struct {
	IfIdx    uint32
	SubIfIdx uint32
}

// FlowData mirrors WINDIVERT_DATA_FLOW. Addresses are per-UINT32, in the
// driver's native (little-endian) order; see WinDivertHelperNtohIPv6Address
// in the upstream API for conversion. For IPv4, LocalAddr[0] holds the
// address in host byte order.
type FlowData struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16 // host byte order
	RemotePort       uint16 // host byte order
	Protocol         uint8  // IPPROTO_* (6 = TCP, 17 = UDP)
}

// SocketData mirrors WINDIVERT_DATA_SOCKET; identical layout to FlowData.
type SocketData = FlowData

// ReflectData mirrors WINDIVERT_DATA_REFLECT.
type ReflectData struct {
	Timestamp int64 // Handle open time.
	ProcessID uint32
	Layer     uint32
	Flags     uint64
	Priority  int16
}

// Network returns the NETWORK / NETWORK_FORWARD layer view of the address
// union. The returned pointer aliases Address.Data; it is valid as long as
// the Address is.
func (a *Address) Network() *NetworkData {
	return (*NetworkData)(unsafe.Pointer(&a.Data[0]))
}

// Flow returns the FLOW layer view of the address union (aliases Data).
func (a *Address) Flow() *FlowData {
	return (*FlowData)(unsafe.Pointer(&a.Data[0]))
}

// Socket returns the SOCKET layer view of the address union (aliases Data).
func (a *Address) Socket() *SocketData {
	return (*SocketData)(unsafe.Pointer(&a.Data[0]))
}

// Reflect returns the REFLECT layer view of the address union (aliases Data).
func (a *Address) Reflect() *ReflectData {
	return (*ReflectData)(unsafe.Pointer(&a.Data[0]))
}

// Raw encodes the address into its 80-byte on-wire (little-endian) form.
func (a *Address) Raw() [AddressSize]byte {
	var b [AddressSize]byte
	binary.LittleEndian.PutUint64(b[0:8], uint64(a.Timestamp))
	b[8] = a.Layer
	b[9] = a.Event
	b[10] = a.flags
	b[11] = a.Reserved1
	binary.LittleEndian.PutUint32(b[12:16], a.Reserved2)
	copy(b[16:80], a.Data[:])
	return b
}

// ParseAddress decodes a WINDIVERT_ADDRESS from its raw 80-byte wire form
// (as stored by WinDivertRecvEx address arrays or read from packet dumps).
func ParseAddress(b []byte) (Address, error) {
	var a Address
	if len(b) < AddressSize {
		return a, fmt.Errorf("windivert: address buffer too short: got %d bytes, want %d", len(b), AddressSize)
	}
	a.Timestamp = int64(binary.LittleEndian.Uint64(b[0:8]))
	a.Layer = b[8]
	a.Event = b[9]
	a.flags = b[10]
	a.Reserved1 = b[11]
	a.Reserved2 = binary.LittleEndian.Uint32(b[12:16])
	copy(a.Data[:], b[16:80])
	return a, nil
}
