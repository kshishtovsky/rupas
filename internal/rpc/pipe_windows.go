//go:build windows

package rpc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Named-pipe flags (values per the Win32 API; modern stdlib syscall no
// longer exports the named-pipe entry points, so they are bound directly
// via LazyDLL — still stdlib-only).
const (
	pipeAccessDuplex   = 0x00000003 // PIPE_ACCESS_DUPLEX
	fileFlagOverlapped = 0x40000000 // FILE_FLAG_OVERLAPPED
	pipeTypeByte       = 0x00000000
	pipeReadmodeByte   = 0x00000000
	pipeWait           = 0x00000000
	pipeRejectRemote   = 0x00000008  // PIPE_REJECT_REMOTE_CLIENTS
	pipeUnlimitedInst  = 255         // PIPE_UNLIMITED_INSTANCES
	fileGenericRW      = 0xC0000000  // GENERIC_READ|GENERIC_WRITE
	openExisting       = 3           // OPEN_EXISTING
	infiniteWait       = 0xFFFFFFFF  // INFINITE
	invalidHandle      = ^uintptr(0) // INVALID_HANDLE_VALUE

	errnoPipeConnected = syscall.Errno(535) // ERROR_PIPE_CONNECTED
	errnoPipeBusy      = syscall.Errno(231) // ERROR_PIPE_BUSY
	errnoNoData        = syscall.Errno(232) // ERROR_NO_DATA
	errnoIOPending     = syscall.Errno(997) // ERROR_IO_PENDING
	errnoOpAborted     = syscall.Errno(995) // ERROR_OPERATION_ABORTED
)

// pipeSDDL is the security descriptor for the pipe DACL (§9: ACL =
// interactive user + SYSTEM):
//
//	D:P          — DACL, protected (no inherited ACEs)
//	(A;;GA;;;SY) — SYSTEM: full access
//	(A;;GA;;;IU) — Interactive user: full access
//
// TODO(security): this is the stdlib-only substitute for a winio-style
// explicit peer token check. Accepted limitations, to revisit:
//   - the peer is authorized by the DACL at connect time only; the server
//     does not re-validate the client token (GetNamedPipeClientProcessId
//   - SID allowlist) afterwards;
//   - remote (SMB) clients are rejected via PIPE_REJECT_REMOTE_CLIENTS;
//   - no per-command granular ACLs and no RPS cap on the pipe yet (§10).
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;IU)"

// pipeInstances is how many concurrently-connectable instances we pre-arm.
const pipeInstances = 4

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procConvSDDLToSD    = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFree       = kernel32.NewProc("LocalFree")
	procWaitNamedPipe   = kernel32.NewProc("WaitNamedPipeW")
	procCreateNamedPipe = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPi  = kernel32.NewProc("ConnectNamedPipe")
	procCreateFileW     = kernel32.NewProc("CreateFileW")
	procCreateEventW    = kernel32.NewProc("CreateEventW")
	procCancelIoEx      = kernel32.NewProc("CancelIoEx")
	procGetOvResult     = kernel32.NewProc("GetOverlappedResult")
	procWaitForSingle   = kernel32.NewProc("WaitForSingleObject")
)

// sddlSecurityAttributes builds SECURITY_ATTRIBUTES wrapping a descriptor
// parsed from sddl. The descriptor is freed by pipeListener.Close.
func sddlSecurityAttributes(sddl string) (*syscall.SecurityAttributes, uintptr, error) {
	p, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return nil, 0, err
	}
	var sd uintptr
	r1, _, e1 := procConvSDDLToSD.Call(
		uintptr(unsafe.Pointer(p)),
		1, // SDDL_REVISION_1
		uintptr(unsafe.Pointer(&sd)),
		0,
	)
	if r1 == 0 || sd == 0 {
		return nil, 0, fmt.Errorf("SDDL %q: %w", sddl, e1)
	}
	sa := &syscall.SecurityAttributes{
		InheritHandle:      0,
		SecurityDescriptor: sd, // uintptr per stdlib syscall on Windows
	}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, sd, nil
}

// createEvent returns an unnamed manual-reset event for overlapped waits.
func createEvent() (syscall.Handle, error) {
	r1, _, e1 := procCreateEventW.Call(0, 0, 1, 0)
	if r1 == 0 {
		return 0, e1
	}
	return syscall.Handle(r1), nil
}

// createNamedPipe wraps CreateNamedPipeW with SECURITY_ATTRIBUTES; the
// instance is OVERLAPPED so pending connects can be cancelled on shutdown.
func createNamedPipe(name *uint16, sa *syscall.SecurityAttributes) (syscall.Handle, error) {
	r1, _, e1 := procCreateNamedPipe.Call(
		uintptr(unsafe.Pointer(name)),
		pipeAccessDuplex|fileFlagOverlapped,
		pipeTypeByte|pipeReadmodeByte|pipeWait|pipeRejectRemote,
		pipeUnlimitedInst,
		65536, // out buffer
		65536, // in buffer
		0,     // default timeout
		uintptr(unsafe.Pointer(sa)),
	)
	if r1 == invalidHandle {
		return 0, e1
	}
	return syscall.Handle(r1), nil
}

// waitConnect issues an OVERLAPPED ConnectNamedPipe and blocks until a
// client arrives or the operation is cancelled via CancelIoEx (Close).
// This is the winio pattern on stdlib primitives: a blocking
// ConnectNamedPipe on a sync handle can NOT be unblocked by CloseHandle,
// which is why the OVERLAPPED route is mandatory. Returns nil once a
// client is connected.
func waitConnect(h syscall.Handle) error {
	ev, err := createEvent()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(ev)

	ov := &syscall.Overlapped{HEvent: ev}
	r1, _, e1 := procConnectNamedPi.Call(uintptr(h), uintptr(unsafe.Pointer(ov)))
	if r1 != 0 {
		return nil // connected immediately
	}
	switch e1.(syscall.Errno) {
	case errnoPipeConnected, errnoNoData:
		// The client won the create/connect race (and possibly left
		// already): serve the connection; the first read just EOFs.
		return nil
	case errnoIOPending:
		// Wait for completion (a client) or cancellation (Close).
		w, _, _ := procWaitForSingle.Call(uintptr(ev), infiniteWait)
		var transferred uint32
		res, _, gerr := procGetOvResult.Call(uintptr(h), uintptr(unsafe.Pointer(ov)), uintptr(unsafe.Pointer(&transferred)), 0)
		if res != 0 {
			return nil
		}
		if errors.Is(gerr, errnoOpAborted) || w == 0xFFFFFFFF { // WAIT_FAILED
			return errnoOpAborted
		}
		return gerr
	default:
		return e1
	}
}

// cancelIo aborts pending overlapped I/O on the handle, waking the
// goroutine blocked in waitConnect.
func cancelIo(h syscall.Handle) {
	procCancelIoEx.Call(uintptr(h), 0)
}

// pipeListener is a named-pipe accept loop with a fixed pool of instance
// goroutines.
type pipeListener struct {
	name    string
	sa      *syscall.SecurityAttributes
	sd      uintptr // LocalFree'd on Close
	namePtr *uint16

	mu      sync.Mutex
	closed  bool
	pending map[syscall.Handle]struct{} // instances blocked in waitConnect

	conns chan *os.File
	errCh chan error
	done  chan struct{}
	wg    sync.WaitGroup
}

func newPipeListener(name string) (listener, error) {
	sa, sd, err := sddlSecurityAttributes(pipeSDDL)
	if err != nil {
		return nil, err
	}
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		procLocalFree.Call(sd)
		return nil, err
	}
	pl := &pipeListener{
		name:    name,
		sa:      sa,
		sd:      sd,
		namePtr: namePtr,
		pending: make(map[syscall.Handle]struct{}),
		conns:   make(chan *os.File, pipeInstances),
		errCh:   make(chan error, 1),
		done:    make(chan struct{}),
	}
	for i := 0; i < pipeInstances; i++ {
		pl.wg.Add(1)
		go pl.instanceLoop()
	}
	return pl, nil
}

// instanceLoop owns one pipe slot: create an instance, wait for a client,
// hand the connection to Accept, repeat.
func (pl *pipeListener) instanceLoop() {
	defer pl.wg.Done()
	for {
		h, err := createNamedPipe(pl.namePtr, pl.sa)
		if err != nil {
			pl.fail(err)
			return
		}
		pl.mu.Lock()
		if pl.closed {
			pl.mu.Unlock()
			syscall.CloseHandle(h)
			return
		}
		pl.pending[h] = struct{}{}
		pl.mu.Unlock()

		err = waitConnect(h)

		pl.mu.Lock()
		delete(pl.pending, h)
		closed := pl.closed
		pl.mu.Unlock()

		if closed || errors.Is(err, errnoOpAborted) {
			syscall.CloseHandle(h)
			return
		}
		if err != nil {
			syscall.CloseHandle(h)
			pl.fail(err)
			return
		}

		f := os.NewFile(uintptr(h), pl.name+" [server]")
		select {
		case pl.conns <- f:
		case <-pl.done:
			f.Close()
			return
		}
	}
}

func (pl *pipeListener) fail(err error) {
	select {
	case pl.errCh <- err:
	default:
	}
}

func (pl *pipeListener) Accept() (io.ReadWriteCloser, error) {
	select {
	case f := <-pl.conns:
		return f, nil
	case err := <-pl.errCh:
		return nil, err
	case <-pl.done:
		return nil, os.ErrClosed
	}
}

func (pl *pipeListener) Close() error {
	pl.mu.Lock()
	if pl.closed {
		pl.mu.Unlock()
		return nil
	}
	pl.closed = true
	close(pl.done)
	pending := make([]syscall.Handle, 0, len(pl.pending))
	for h := range pl.pending {
		pending = append(pending, h)
	}
	pl.pending = nil
	pl.mu.Unlock()

	// Cancel pending connects; the instance loops close their own handles
	// and exit. (CloseHandle alone cannot unblock a pending connect.)
	for _, h := range pending {
		cancelIo(h)
	}
	pl.wg.Wait()
	if pl.sd != 0 {
		procLocalFree.Call(pl.sd)
		pl.sd = 0
	}
	return nil
}

// DialPipe connects a client to a named pipe (opened OVERLAPPED so
// os.File I/O integrates with the Go poller), waiting for a free instance
// while the pipe is busy, up to timeout.
func DialPipe(name string, timeout time.Duration) (*os.File, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for {
		f, err := openPipeOverlapped(name, namePtr)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, errnoPipeBusy) {
			return nil, err
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return nil, os.ErrDeadlineExceeded
		}
		procWaitNamedPipe.Call(uintptr(unsafe.Pointer(namePtr)), uintptr(rem.Milliseconds()))
	}
}

func openPipeOverlapped(name string, namePtr *uint16) (*os.File, error) {
	r1, _, e1 := procCreateFileW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		fileGenericRW,
		0, // no sharing
		0, // default security; the server-side DACL gates the connect
		openExisting,
		fileFlagOverlapped,
		0,
	)
	if r1 == invalidHandle {
		return nil, e1
	}
	return os.NewFile(r1, name), nil
}
