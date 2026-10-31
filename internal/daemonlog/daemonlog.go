// Package daemonlog writes the daemon's log to a size-rotated file so a
// long-running daemon cannot fill the disk: rupasd.log rotates to .1, .2 …
// and the oldest file past keep is dropped.
package daemonlog

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer is an io.Writer over a rotating log file. Rotation happens before a
// write that would cross max bytes, so one file never exceeds max + one line.
type Writer struct {
	path string
	max  int64
	keep int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// New opens (or creates) path and returns a rotating writer keeping keep files
// of max bytes each.
func New(path string, max int64, keep int) (*Writer, error) {
	if max <= 0 {
		max = 10 << 20
	}
	if keep <= 0 {
		keep = 5
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	w := &Writer{path: path, max: max, keep: keep}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Write appends p, rotating first if the file is full. A failing rotation
// keeps the old file open rather than dropping the line.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.size+int64(len(p)) > w.max {
		w.rotate()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate shifts rupasd.log → .1 → .2 … and reopens a fresh file.
func (w *Writer) rotate() {
	w.f.Close()
	// Oldest is dropped, the rest shift by one: .keep-1 disappears first.
	os.Remove(fmt.Sprintf("%s.%d", w.path, w.keep))
	for i := w.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	os.Rename(w.path, w.path+".1")
	if err := w.open(); err != nil {
		w.f = nil
	}
}

// Close closes the current file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
