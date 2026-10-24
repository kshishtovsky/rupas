//go:build windows

package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Handle is an open WinDivert handle. All methods are safe for use from a
// single goroutine; the hot path (SYSTEM_DESIGN §3.2) uses one goroutine per
// layer.
type Handle struct {
	h uintptr

	// Layer and Priority record the open parameters for diagnostics.
	Layer    uint8
	Priority int16
}

// Open opens a WinDivert handle with flags = 0, i.e. packets matching the
// filter are intercepted (blocked from the stack) until re-injected with
// Send. For passive capture use OpenWithFlags with FlagSniff.
//
// filter is a WinDivert filter-language expression (ASCII, see
// FilterBuilder); layer is one of the Layer* constants; priority orders
// handles (-30000..30000, higher consulted first; 0 is fine for a single
// handle).
//
// Open requires administrator privileges and the WinDivert driver service;
// on failure the error carries the GetLastError code (e.g. 5 for access
// denied, 87 for an invalid filter or unsupported layer such as
// LayerRedirect on the stock DLL).
func Open(filter string, layer uint8, priority int16) (*Handle, error) {
	return OpenWithFlags(filter, layer, priority, 0)
}

// OpenWithFlags is Open with explicit WINDIVERT_FLAG_* flags.
func OpenWithFlags(filter string, layer uint8, priority int16, flags uint64) (*Handle, error) {
	if err := procOpen.Find(); err != nil {
		return nil, dllErr(err)
	}
	if layer > LayerRedirect {
		return nil, fmt.Errorf("windivert: invalid layer %d (valid range 0..%d)", layer, LayerRedirect)
	}
	if len(filter) > MaxFilterLen {
		return nil, ErrFilterTooLong
	}
	// The filter is a plain C string (const char *), not UTF-16.
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, fmt.Errorf("windivert: filter: %w", err)
	}
	r1, _, e1 := procOpen.Call(
		uintptr(unsafe.Pointer(f)),
		uintptr(layer),
		uintptr(uint16(priority)), // int16 sign preserved in the low 16 bits
		uintptr(flags),
	)
	if r1 == 0 || r1 == invalidHandle {
		return nil, callErr("WinDivertOpen", e1)
	}
	return &Handle{h: r1, Layer: layer, Priority: priority}, nil
}

func (h *Handle) valid() error {
	if h == nil || h.h == 0 || h.h == invalidHandle {
		return ErrClosed
	}
	return nil
}

// Close releases the handle. Any packets still queued in the driver are
// re-injected automatically by the driver. Close is idempotent.
func (h *Handle) Close() error {
	if h == nil || h.h == 0 || h.h == invalidHandle {
		return nil
	}
	if err := procClose.Find(); err != nil {
		return dllErr(err)
	}
	r1, _, e1 := procClose.Call(h.h)
	h.h = 0
	if r1 == 0 {
		return callErr("WinDivertClose", e1)
	}
	return nil
}

// Recv receives one packet into buf, filling addr with its WINDIVERT_ADDRESS.
// It blocks until a packet matching the filter arrives or the handle is shut
// down / closed. It returns the number of bytes written into buf.
func (h *Handle) Recv(buf []byte, addr *Address) (int, error) {
	if err := h.valid(); err != nil {
		return 0, err
	}
	if err := procRecv.Find(); err != nil {
		return 0, dllErr(err)
	}
	if len(buf) == 0 {
		return 0, errors.New("windivert: Recv into empty buffer")
	}
	var (
		n  uint32
		ap uintptr
	)
	if addr != nil {
		ap = uintptr(unsafe.Pointer(addr))
	}
	r1, _, e1 := procRecv.Call(
		h.h,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)), // pRecvLen (4th argument, per windivert.h)
		ap,                          // pAddr (5th argument)
	)
	if r1 == 0 {
		return 0, callErr("WinDivertRecv", e1)
	}
	return int(n), nil
}

// Send re-injects (or injects, for crafted packets) pkt with the metadata in
// addr (usually the Address from the matching Recv, with Outbound() flipped
// if the direction changes). The driver always sends the full packet; a
// short-write is reported as an error.
func (h *Handle) Send(pkt []byte, addr *Address) error {
	if err := h.valid(); err != nil {
		return err
	}
	if err := procSend.Find(); err != nil {
		return dllErr(err)
	}
	if len(pkt) == 0 {
		return errors.New("windivert: Send of empty packet")
	}
	var (
		sent uint32
		ap   uintptr
	)
	if addr != nil {
		ap = uintptr(unsafe.Pointer(addr))
	}
	r1, _, e1 := procSend.Call(
		h.h,
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sent)), // pSendLen (4th argument, per windivert.h)
		ap,                             // pAddr (5th argument)
	)
	if r1 == 0 {
		return callErr("WinDivertSend", e1)
	}
	if int(sent) != len(pkt) {
		return fmt.Errorf("windivert: WinDivertSend wrote %d of %d bytes", sent, len(pkt))
	}
	return nil
}

// RecvBatch receives up to len(packets) packets in a single WinDivertRecvEx
// call (the official WinDivert 2.2 batch API; the fork-only
// WinDivertRecvBatch export is NOT present in this DLL). It returns the
// number of packets received; each packets[i] is re-sliced to the actual
// packet length and addrs[i] holds its address.
//
// Contract: every packets[i] must be a non-empty sub-slice of ONE contiguous
// backing buffer, in increasing address order without overlap; use NewBatch
// to build such a setup. Packet boundaries are recovered from the IP header
// total-length fields, because stock 2.2 returns only the aggregate byte
// count. Note: WinDivertRecvEx returns as soon as at least one packet is
// available; there is no wait-for-full-batch mode.
func (h *Handle) RecvBatch(packets [][]byte, addrs []Address) (int, error) {
	if err := h.valid(); err != nil {
		return 0, err
	}
	if err := procRecvEx.Find(); err != nil {
		return 0, dllErr(err)
	}
	n := len(packets)
	if n > len(addrs) {
		n = len(addrs)
	}
	if n == 0 {
		return 0, nil
	}
	for i := 0; i < n; i++ {
		if len(packets[i]) == 0 {
			return 0, errors.New("windivert: RecvBatch slot is empty")
		}
	}
	lo := unsafe.Pointer(&packets[0][0])
	loU := uintptr(lo)
	spanEnd := loU + uintptr(len(packets[0]))
	for i := 1; i < n; i++ {
		start := uintptr(unsafe.Pointer(&packets[i][0]))
		if start < spanEnd { // unordered or overlapping
			return 0, errors.New("windivert: RecvBatch slots must be ordered, non-overlapping views of one buffer")
		}
		spanEnd = start + uintptr(len(packets[i]))
	}
	var (
		total   uint32
		addrLen = uint32(n) * AddressSize
	)
	r1, _, e1 := procRecvEx.Call(
		h.h,
		loU,                                // pPacket
		spanEnd-loU,                        // packetLen (span of the whole batch buffer)
		uintptr(unsafe.Pointer(&total)),    // pRecvLen
		0,                                  // flags: must be zero
		uintptr(unsafe.Pointer(&addrs[0])), // pAddr array
		uintptr(unsafe.Pointer(&addrLen)),  // pAddrLen: in = capacity, out = used
		0,                                  // lpOverlapped: synchronous
	)
	runtime.KeepAlive(packets)
	runtime.KeepAlive(addrs)
	if r1 == 0 {
		return 0, callErr("WinDivertRecvEx", e1)
	}
	cnt := int(addrLen) / AddressSize
	if err := splitBatch(packets, lo, int(total), cnt); err != nil {
		return 0, fmt.Errorf("windivert: RecvEx returned %d bytes / %d addresses: %w", total, cnt, err)
	}
	return cnt, nil
}

// splitBatch re-slices packets[0:count] to per-packet lengths, walking the
// IP total-length fields starting at base. base+total must cover exactly
// count back-to-back packets.
func splitBatch(packets [][]byte, base unsafe.Pointer, total, count int) error {
	off := 0
	for i := 0; i < count; i++ {
		plen, err := packetLenAt(unsafe.Add(base, off), total-off)
		if err != nil {
			return err
		}
		packets[i] = unsafe.Slice((*byte)(unsafe.Add(base, off)), plen)
		off += plen
	}
	if off != total {
		return fmt.Errorf("sum of IP total lengths %d != received %d", off, total)
	}
	return nil
}

// packetLenAt determines a packet's length from its IPv4/IPv6 header.
func packetLenAt(p unsafe.Pointer, max int) (int, error) {
	if max < 20 {
		return 0, fmt.Errorf("trailing %d bytes: too short for an IP header", max)
	}
	b := unsafe.Slice((*byte)(p), max)
	switch b[0] >> 4 {
	case 4:
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if l < 20 || l > max {
			return 0, fmt.Errorf("IPv4 total length %d out of range (max %d)", l, max)
		}
		return l, nil
	case 6:
		l := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if l < 40 || l > max {
			return 0, fmt.Errorf("IPv6 length %d out of range (max %d)", l, max)
		}
		return l, nil
	default:
		return 0, fmt.Errorf("bad IP version %d", b[0]>>4)
	}
}

// NewBatch allocates a batch-receive setup: one contiguous buffer of n
// slots x each bytes, matching ordered slot views, and an address array.
// The typical hot-path shape is n <= 64 (SYSTEM_DESIGN §3.2).
func NewBatch(n, each int) (buf []byte, packets [][]byte, addrs []Address) {
	buf = make([]byte, n*each)
	packets = make([][]byte, n)
	for i := range packets {
		packets[i] = buf[i*each : (i+1)*each]
	}
	addrs = make([]Address, n)
	return buf, packets, addrs
}

// Shutdown shuts down the receive and/or send side of the handle. Pending
// and future Recv calls unblock and fail; use ShutdownRecv to cancel a
// blocked Recv goroutine.
func (h *Handle) Shutdown(how uint8) error {
	if err := h.valid(); err != nil {
		return err
	}
	if err := procShutdown.Find(); err != nil {
		return dllErr(err)
	}
	r1, _, e1 := procShutdown.Call(h.h, uintptr(how))
	if r1 == 0 {
		return callErr("WinDivertShutdown", e1)
	}
	return nil
}

// SetParam sets a handle parameter (queue length/time/size).
func (h *Handle) SetParam(param int, value uint64) error {
	if err := h.valid(); err != nil {
		return err
	}
	if err := procSetParam.Find(); err != nil {
		return dllErr(err)
	}
	r1, _, e1 := procSetParam.Call(h.h, uintptr(param), uintptr(value))
	if r1 == 0 {
		return callErr("WinDivertSetParam", e1)
	}
	return nil
}

// GetParam reads a handle parameter; ParamVersionMajor/Minor return the
// driver version (2.2 for the build shipped in build/windivert).
func (h *Handle) GetParam(param int) (uint64, error) {
	if err := h.valid(); err != nil {
		return 0, err
	}
	if err := procGetParam.Find(); err != nil {
		return 0, dllErr(err)
	}
	var v uint64
	r1, _, e1 := procGetParam.Call(h.h, uintptr(param), uintptr(unsafe.Pointer(&v)))
	if r1 == 0 {
		return 0, callErr("WinDivertGetParam", e1)
	}
	return v, nil
}

// CalcChecksums recomputes all IPv4/ICMP/ICMPv6/TCP/UDP checksums of pkt in
// place (flag 0 = recompute everything) and updates the checksum-valid bits
// in addr. It is a pure userspace helper; addr may be nil.
func CalcChecksums(pkt []byte, addr *Address) error {
	return CalcChecksumsWithFlags(pkt, addr, 0)
}

// CalcChecksumsWithFlags is CalcChecksums with WINDIVERT_HELPER_NO_* flags
// to skip individual checksums.
func CalcChecksumsWithFlags(pkt []byte, addr *Address, flags uint64) error {
	if err := procHelperCalcChecksums.Find(); err != nil {
		return dllErr(err)
	}
	if len(pkt) == 0 {
		return errors.New("windivert: CalcChecksums of empty packet")
	}
	var ap uintptr
	if addr != nil {
		ap = uintptr(unsafe.Pointer(addr))
	}
	r1, _, e1 := procHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		ap,
		uintptr(flags),
	)
	if r1 == 0 {
		return callErr("WinDivertHelperCalcChecksums", e1)
	}
	return nil
}

// FilterBuilder incrementally constructs WinDivert filter strings from
// primitives (direction, protocol, ports, CIDR lists), emitting only syntax
// the shipped DLL accepts. Empirically verified against
// WinDivertHelperCompileFilter of build/windivert/WinDivert.dll:
//
//   - "in {...}" sets and CIDR masks ("a.b.c.d/nn") are rejected, so each
//     CIDR becomes an explicit >=/<= range (== for /32 hosts);
//   - IPv6 address literals are rejected (IPv6 stack stripped in this
//     build): IPv6 prefixes fail Build with ErrIPv6FiltersUnsupported;
//   - filters longer than MaxFilterLen are rejected by the DLL; Build
//     pre-checks and returns ErrFilterTooLong.
//
// A nil *FilterBuilder behaves like NewFilter().
type FilterBuilder struct {
	dir      string // "" | "outbound" | "inbound"
	proto    string // "" | "tcp" | "udp" | "icmp"
	dstPorts []uint16
	srcPorts []uint16
	dstCIDRs []netip.Prefix
	srcCIDRs []netip.Prefix
	err      error // first invalid input, returned by Build
}

// NewFilter returns an empty FilterBuilder.
func NewFilter() *FilterBuilder { return &FilterBuilder{} }

// Outbound restricts the filter to outbound packets.
func (b *FilterBuilder) Outbound() *FilterBuilder { b.dir = "outbound"; return b }

// Inbound restricts the filter to inbound packets.
func (b *FilterBuilder) Inbound() *FilterBuilder { b.dir = "inbound"; return b }

// TCP restricts the filter to TCP packets.
func (b *FilterBuilder) TCP() *FilterBuilder { b.proto = "tcp"; return b }

// UDP restricts the filter to UDP packets.
func (b *FilterBuilder) UDP() *FilterBuilder { b.proto = "udp"; return b }

// ICMP restricts the filter to ICMP packets.
func (b *FilterBuilder) ICMP() *FilterBuilder { b.proto = "icmp"; return b }

// DstPorts adds destination ports to match (any-of).
func (b *FilterBuilder) DstPorts(ports ...uint16) *FilterBuilder {
	b.dstPorts = append(b.dstPorts, ports...)
	return b
}

// SrcPorts adds source ports to match (any-of).
func (b *FilterBuilder) SrcPorts(ports ...uint16) *FilterBuilder {
	b.srcPorts = append(b.srcPorts, ports...)
	return b
}

// DstCIDRs adds destination CIDRs to match (any-of). Invalid or IPv6 CIDRs
// are remembered and reported by Build.
func (b *FilterBuilder) DstCIDRs(cidrs ...string) *FilterBuilder {
	b.appendCIDRs(&b.dstCIDRs, cidrs)
	return b
}

// SrcCIDRs adds source CIDRs to match (any-of). Invalid or IPv6 CIDRs are
// remembered and reported by Build.
func (b *FilterBuilder) SrcCIDRs(cidrs ...string) *FilterBuilder {
	b.appendCIDRs(&b.srcCIDRs, cidrs)
	return b
}

func (b *FilterBuilder) appendCIDRs(dst *[]netip.Prefix, cidrs []string) {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			if b.err == nil {
				b.err = fmt.Errorf("windivert: invalid CIDR %q: %w", c, err)
			}
			continue
		}
		if !p.Addr().Is4() {
			if b.err == nil {
				b.err = fmt.Errorf("%w: %s", ErrIPv6FiltersUnsupported, c)
			}
			continue
		}
		*dst = append(*dst, p)
	}
}

// Build renders the final filter string, or "true" for an empty builder.
func (b *FilterBuilder) Build() (string, error) {
	if b == nil {
		return "true", nil
	}
	if b.err != nil {
		return "", b.err
	}
	if (len(b.dstPorts) > 0 || len(b.srcPorts) > 0) && b.proto != "tcp" && b.proto != "udp" {
		return "", errors.New("windivert: port filter requires TCP() or UDP()")
	}
	var terms []string
	if b.dir != "" {
		terms = append(terms, b.dir)
	}
	if b.proto != "" {
		terms = append(terms, b.proto)
	}
	if c := portsClause(b.proto, "DstPort", b.dstPorts); c != "" {
		terms = append(terms, c)
	}
	if c := portsClause(b.proto, "SrcPort", b.srcPorts); c != "" {
		terms = append(terms, c)
	}
	if c, err := cidrClause("DstAddr", b.dstCIDRs); err != nil {
		return "", err
	} else if c != "" {
		terms = append(terms, c)
	}
	if c, err := cidrClause("SrcAddr", b.srcCIDRs); err != nil {
		return "", err
	} else if c != "" {
		terms = append(terms, c)
	}
	f := strings.Join(terms, " and ")
	if f == "" {
		f = "true"
	}
	if len(f) > MaxFilterLen {
		return "", ErrFilterTooLong
	}
	return f, nil
}

// portsClause renders "tcp.DstPort == 443" or an any-of disjunction.
func portsClause(proto, field string, ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = proto + "." + field + " == " + strconv.FormatUint(uint64(p), 10)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// cidrClause renders an IPv4 CIDR list as ==/range comparisons. The shipped
// DLL has no set syntax and no CIDR literals, so each prefix becomes either
// a host equality (/32) or a >=/<= range, combined with "or".
func cidrClause(field string, cidrs []netip.Prefix) (string, error) {
	if len(cidrs) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(cidrs))
	for _, p := range cidrs {
		if !p.Addr().Is4() {
			return "", fmt.Errorf("%w: %s", ErrIPv6FiltersUnsupported, p)
		}
		lo := p.Masked().Addr()
		if p.Bits() == 32 {
			parts = append(parts, "ip."+field+" == "+lo.String())
			continue
		}
		hi := lastAddr(p)
		parts = append(parts, "(ip."+field+" >= "+lo.String()+" and ip."+field+" <= "+hi.String()+")")
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " or ") + ")", nil
}

// lastAddr returns the last host address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	lo := p.Masked().Addr().As4()
	var hi [4]byte
	copy(hi[:], lo[:])
	hostBits := 32 - p.Bits()
	for i := 3; i >= 0 && hostBits > 0; i-- {
		if hostBits >= 8 {
			hi[i] = 0xFF
			hostBits -= 8
		} else {
			hi[i] |= byte(1<<uint(hostBits)) - 1
			hostBits = 0
		}
	}
	return netip.AddrFrom4(hi)
}
