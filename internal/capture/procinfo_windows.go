//go:build windows

// procinfo_windows.go — PID attribution for the `app:` rule stage: which
// local process owns the socket of a flow (PLAN-0.8 §2).
//
// Fail-open everywhere: no snapshot row, PID 0, or an unopenable process
// yields "" and the app stage simply does not fire.
//
// Known limits (accepted, PLAN-0.8 §2):
//   - a socket missing from the snapshot — UDP datagrams from an unbound
//     socket, anything without a PID row — falls back to the general
//     policy;
//   - a flow opened before the daemon started is attributed on the next
//     snapshot only if the port is still in the table (it is: rows are
//     per-socket, not per-connection-event);
//   - a socket created after the last snapshot is seen only on the next
//     one (≤100 ms), so the first packets of a just-started process may
//     resolve by the general policy;
//   - PID 4 (System) and protected svchost services refuse the query, so
//     app rules cannot tell them apart by name.
package capture

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// MIB table classes and the address family of both snapshots
	// (iphlpapi.h, winsock2.h).
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL: LISTEN + connections
	udpTableOwnerPID    = 1
	afInet              = 2
	// sizeof(MIB_TCPROW_OWNER_PID) / sizeof(MIB_UDPROW_OWNER_PID) and the
	// dwNumEntries header both tables start with.
	tcpRowLen      = 24
	udpRowLen      = 12
	socketTableLen = 4
)

// Cache lifetimes: one snapshot costs ~0.5 ms for ~200 rows, so it is
// shared by the whole process and taken at most 10×/s (0.5 % of a core);
// PID→name is cached longer, as PID reuse is rare but not impossible.
const (
	snapshotTTL = 100 * time.Millisecond
	pidNameTTL  = 5 * time.Second
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// mibTCPRow/mibUDPRow are the MIB row layouts; the port fields are in
// network byte order (hostPort decodes them).
type mibTCPRow struct {
	State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPID uint32
}

type mibUDPRow struct {
	LocalAddr, LocalPort, OwningPID uint32
}

type pidName struct {
	name string
	at   time.Time
}

// procCache is process-wide: one socket snapshot and one PID→name map
// serve every flow.
type procCache struct {
	mu    sync.Mutex
	tcpAt time.Time
	// tcp/udp map a LOCAL port to the owning PID. shortcut: one owner per
	// port — two processes bound to the same port on different addresses
	// resolve to whichever row came last; give the table a (addr, port)
	// key if that ever bites.
	tcp   map[uint16]uint32
	udpAt time.Time
	udp   map[uint16]uint32
	names map[uint32]pidName
}

var procs = procCache{names: make(map[uint32]pidName)}

// procName returns the lower-case basename of the process owning local
// port port ("" when unknown, and always "" for port 0). udp selects the
// UDP socket table. Zero allocations on the cached path.
func procName(port uint16, udp bool) string {
	if port == 0 {
		return ""
	}
	procs.mu.Lock()
	defer procs.mu.Unlock()
	return procs.nameLocked(procs.ownerLocked(port, udp))
}

// ownerLocked resolves port to a PID, refreshing the snapshot when stale.
// The lock is held across the ~0.5 ms syscall on purpose: concurrent flows
// wait for one snapshot instead of each taking their own.
func (c *procCache) ownerLocked(port uint16, udp bool) uint32 {
	at, table, snap := &c.tcpAt, &c.tcp, snapshotTCP
	if udp {
		at, table, snap = &c.udpAt, &c.udp, snapshotUDP
	}
	if *table == nil || time.Since(*at) >= snapshotTTL {
		// A failed snapshot keeps the previous table (attribution stays on
		// the last good view) and still backs off for one TTL.
		if m := snap(); m != nil {
			*table = m
		}
		*at = time.Now()
	}
	return (*table)[port]
}

// nameLocked resolves PID → basename with a 5 s cache (a miss costs an
// OpenProcess + a 260-rune path buffer, too much per packet).
func (c *procCache) nameLocked(pid uint32) string {
	if pid == 0 {
		return ""
	}
	if e, ok := c.names[pid]; ok && time.Since(e.at) < pidNameTTL {
		return e.name
	}
	name := pidBasename(pid)
	c.names[pid] = pidName{name: name, at: time.Now()}
	return name
}

// pidBasename resolves PID → lower-case executable basename; "" when the
// process is gone or refuses PROCESS_QUERY_LIMITED_INFORMATION.
func pidBasename(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || size == 0 {
		return ""
	}
	return strings.ToLower(filepath.Base(windows.UTF16ToString(buf[:size])))
}

// snapshotTCP/snapshotUDP return a fresh local port → PID map (nil when the
// call fails; the caller then keeps failing open).
func snapshotTCP() map[uint16]uint32 {
	return socketTable(procGetExtendedTCPTable, tcpTableOwnerPIDAll, false)
}

func snapshotUDP() map[uint16]uint32 {
	return socketTable(procGetExtendedUDPTable, udpTableOwnerPID, true)
}

// socketTable takes one GetExtended{Tcp,Udp}Table(OWNER_PID) snapshot. Both
// entry points share the signature (pTable, pdwSize, bOrder, ulAf, class,
// Reserved), so one caller serves both.
func socketTable(proc *windows.LazyProc, class uintptr, udp bool) map[uint16]uint32 {
	var size uint32
	// First call only sizes the table: ERROR_INSUFFICIENT_BUFFER (122) is
	// the expected answer, 0 means there is nothing to attribute.
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, class, 0)
	if r == 0 || size <= socketTableLen {
		return nil
	}
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, class, 0)
	if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		// The table grew between the two calls: one retry at the new size.
		if size <= socketTableLen {
			return nil
		}
		buf = make([]byte, size)
		r, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, class, 0)
	}
	if r != 0 {
		return nil
	}
	n := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	rowLen := tcpRowLen
	if udp {
		rowLen = udpRowLen
	}
	if fit := (len(buf) - socketTableLen) / rowLen; n > fit {
		n = fit // dwNumEntries outran the buffer: trust the buffer
	}
	if n <= 0 {
		return nil
	}
	m := make(map[uint16]uint32, n)
	if udp {
		for _, row := range unsafe.Slice((*mibUDPRow)(unsafe.Pointer(&buf[socketTableLen])), n) {
			if row.OwningPID != 0 { // TIME_WAIT/closed sockets: no owner
				m[hostPort(row.LocalPort)] = row.OwningPID
			}
		}
		return m
	}
	for _, row := range unsafe.Slice((*mibTCPRow)(unsafe.Pointer(&buf[socketTableLen])), n) {
		if row.OwningPID != 0 {
			m[hostPort(row.LocalPort)] = row.OwningPID
		}
	}
	return m
}

// hostPort decodes a MIB port field: the 16-bit port sits in network byte
// order in the low half of the DWORD (Windows is little-endian).
func hostPort(dw uint32) uint16 {
	return uint16(dw&0xff)<<8 | uint16(dw>>8&0xff)
}
