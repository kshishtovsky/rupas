//go:build windows

// Package windivert is a minimal, cgo-free Go binding for the WinDivert 2.x
// packet interception API (https://github.com/basil00/WinDivert), per
// SYSTEM_DESIGN.md §3.1 / ADR-2.
//
// The DLL is loaded lazily via syscall.NewLazyDLL (WinAPI stdcall). All
// wrappers translate BOOL/HANDLE failures into Go errors carrying the
// GetLastError value captured around the call.
//
// Repository-specific facts, verified empirically against the driver and DLL
// copied into build/windivert/ (driver version 2.2, service "WinDivert"):
//
//   - The DLL exports only the stock WinDivert 2.x API set (30 exports):
//     no WinDivertRecvBatch and no WinDivertRedirect* exports. RecvBatch is
//     therefore implemented on top of the official WinDivertRecvEx.
//   - Layer 5 (REDIRECT) exists only in the Flowseal/zapret-winws fork; this
//     DLL rejects it with ERROR_INVALID_PARAMETER (87). The LayerRedirect
//     constant is defined so capture code can target the fork without magic
//     numbers, but Open fails on the stock DLL.
//   - WinDivertHelperCompileFilter rejects "in {...}" set syntax, CIDR masks
//     ("a.b.c.d/nn") and IPv6 address literals ("bad token"). FilterBuilder
//     emits explicit >=/<= range comparisons for IPv4 CIDRs and refuses
//     IPv6 prefixes.
//   - The WinDivert filter string is a plain C string (const char *), not
//     UTF-16; filters are pure ASCII anyway.
package windivert

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// WinDivert layers (WINDIVERT_LAYER enum). Values 0..4 are upstream;
// see LayerRedirect for the fork-only layer 5.
const (
	LayerNetwork        uint8 = 0 // Packet receive/inject at the network layer.
	LayerNetworkForward uint8 = 1 // Forwarded (routed, not local) packets.
	LayerFlow           uint8 = 2 // Flow established/deleted events.
	LayerSocket         uint8 = 3 // Socket bind/connect/listen/accept/close events.
	LayerReflect        uint8 = 4 // Events about other WinDivert handles.
)

// LayerRedirect is layer 5 of the Flowseal/zapret-winws WinDivert fork,
// used for transparent redirection (SYSTEM_DESIGN §3.3). The stock 2.2 DLL
// shipped in build/windivert rejects it with ERROR_INVALID_PARAMETER
// (verified against the running driver); the constant is kept so code
// written for the fork compiles and runs unchanged once that DLL is swapped
// in.
const LayerRedirect uint8 = 5

// WinDivert events (WINDIVERT_EVENT enum), carried in Address.Event.
const (
	EventNetworkPacket   uint8 = 0
	EventFlowEstablished uint8 = 1
	EventFlowDeleted     uint8 = 2
	EventSocketBind      uint8 = 3
	EventSocketConnect   uint8 = 4
	EventSocketListen    uint8 = 5
	EventSocketAccept    uint8 = 6
	EventSocketClose     uint8 = 7
	EventReflectOpen     uint8 = 8
	EventReflectClose    uint8 = 9
)

// WinDivertOpen flags (WINDIVERT_FLAG_*).
const (
	FlagSniff     uint64 = 0x0001 // Do not intercept; observe only.
	FlagDrop      uint64 = 0x0002 // Drop instead of intercepting.
	FlagRecvOnly  uint64 = 0x0004 // Read-only handle (a.k.a. READ_ONLY).
	FlagSendOnly  uint64 = 0x0008 // Write-only handle (a.k.a. WRITE_ONLY).
	FlagNoInstall uint64 = 0x0010 // Fail if the driver is not already installed.
	FlagFragments uint64 = 0x0020 // Also capture fragmented packets.
)

// WinDivert handle parameters (WINDIVERT_PARAM enum).
const (
	ParamQueueLength  = 0
	ParamQueueTime    = 1
	ParamQueueSize    = 2
	ParamVersionMajor = 3
	ParamVersionMinor = 4
)

// WinDivert shutdown modes (WINDIVERT_SHUTDOWN enum).
const (
	ShutdownRecv uint8 = 1 // Stop the receive side; unblocks pending Recv.
	ShutdownSend uint8 = 2
	ShutdownBoth uint8 = 3
)

// Priority bounds (WINDIVERT_PRIORITY_*).
const (
	PriorityHighest int16 = 30000
	PriorityLowest  int16 = -30000
)

// Batch and packet size limits (WINDIVERT_BATCH_MAX / WINDIVERT_MTU_MAX).
const (
	BatchMax uint32 = 0xFF
	MTUMax   uint32 = 40 + 0xFFFF
)

// MaxFilterLen is the maximum filter string length accepted by WinDivert.
// The compiler rejects longer strings with "Filter expression too long"
// (verified: 6076 bytes compile, 9226 do not; the internal limit is 8192).
const MaxFilterLen = 8192

// Helper flags for CalcChecksumsWithFlags (WINDIVERT_HELPER_NO_*).
const (
	HelperNoIPChecksum     uint64 = 1
	HelperNoICMPChecksum   uint64 = 2
	HelperNoICMPv6Checksum uint64 = 4
	HelperNoTCPChecksum    uint64 = 8
	HelperNoUDPChecksum    uint64 = 16
)

// Sentinel errors returned by this package.
var (
	// ErrClosed is returned by Handle methods used after Close.
	ErrClosed = errors.New("windivert: handle is closed")
	// ErrFilterTooLong is returned by builders when a filter would exceed
	// MaxFilterLen and be rejected by the DLL.
	ErrFilterTooLong = fmt.Errorf("windivert: filter longer than %d characters", MaxFilterLen)
	// ErrIPv6FiltersUnsupported: the WinDivert build shipped in
	// build/windivert strips IPv6 support and rejects IPv6 address
	// literals in filters ("bad token").
	ErrIPv6FiltersUnsupported = errors.New("windivert: IPv6 address literals are rejected by this WinDivert build")
)

const invalidHandle = ^uintptr(0)

// errInvalidParameter is ERROR_INVALID_PARAMETER (87), returned by
// WinDivertOpen for bad filters and unsupported layers (e.g. LayerRedirect
// on the stock DLL).
const errInvalidParameter = syscall.Errno(87)

var (
	modWindivert = syscall.NewLazyDLL("WinDivert.dll")

	procOpen                = modWindivert.NewProc("WinDivertOpen")
	procClose               = modWindivert.NewProc("WinDivertClose")
	procRecv                = modWindivert.NewProc("WinDivertRecv")
	procRecvEx              = modWindivert.NewProc("WinDivertRecvEx")
	procSend                = modWindivert.NewProc("WinDivertSend")
	procShutdown            = modWindivert.NewProc("WinDivertShutdown")
	procSetParam            = modWindivert.NewProc("WinDivertSetParam")
	procGetParam            = modWindivert.NewProc("WinDivertGetParam")
	procHelperCalcChecksums = modWindivert.NewProc("WinDivertHelperCalcChecksums")
	procHelperParsePacket   = modWindivert.NewProc("WinDivertHelperParsePacket")
	procHelperCompileFilter = modWindivert.NewProc("WinDivertHelperCompileFilter")
)

// Available reports whether WinDivert.dll can be loaded from the standard
// DLL search path (application directory, system directories, PATH). It
// does not touch the driver.
func Available() bool { return modWindivert.Load() == nil }

// ValidateFilter compiles a filter string with WinDivertHelperCompileFilter
// without opening a handle. On failure it returns the compiler message and
// error position. It is a pure userspace call (no driver interaction).
func ValidateFilter(filter string, layer uint8) error {
	if err := procHelperCompileFilter.Find(); err != nil {
		return dllErr(err)
	}
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return fmt.Errorf("windivert: filter: %w", err)
	}
	var (
		errStr *byte
		errPos uint32
	)
	r1, _, _ := procHelperCompileFilter.Call(
		uintptr(unsafe.Pointer(f)),
		uintptr(layer),
		0, // object buffer: not requested
		0, // object buffer length
		uintptr(unsafe.Pointer(&errStr)),
		uintptr(unsafe.Pointer(&errPos)),
	)
	if r1 == 0 {
		if errStr != nil {
			return fmt.Errorf("windivert: invalid filter at offset %d: %s", errPos, bytePtrToString(errStr))
		}
		return fmt.Errorf("windivert: invalid filter at offset %d", errPos)
	}
	return nil
}

// dllErr wraps a LazyProc/LazyDLL Find failure.
func dllErr(err error) error {
	return fmt.Errorf("windivert: WinDivert.dll not available: %w", err)
}

// callErr converts the failure of a BOOL/HANDLE-returning WinDivert call
// into a Go error carrying the GetLastError value captured by LazyProc.Call.
func callErr(fn string, e error) error {
	var errno syscall.Errno
	if errors.As(e, &errno) && errno != 0 {
		if errno == errInvalidParameter {
			return fmt.Errorf("windivert: %s: %w (invalid parameter: bad filter syntax or unsupported layer? see ValidateFilter)", fn, errno)
		}
		return fmt.Errorf("windivert: %s: %w", fn, errno)
	}
	if e != nil {
		return fmt.Errorf("windivert: %s: %w", fn, e)
	}
	return fmt.Errorf("windivert: %s failed", fn)
}

// bytePtrToString decodes a NUL-terminated C string owned by the DLL.
func bytePtrToString(p *byte) string {
	if p == nil {
		return ""
	}
	n := 0
	for ptr := unsafe.Pointer(p); *(*byte)(ptr) != 0; ptr = unsafe.Pointer(uintptr(ptr) + 1) {
		n++
	}
	return string(unsafe.Slice(p, n))
}
