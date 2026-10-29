//go:build windows

// procs_windows.go — the process picker behind `app:` rules (PLAN-0.8 §1.1).
package guictrl

import (
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

// ProcView is one picker row: Name is what a rule stores (basename,
// lower-case), Path is shown as the hint.
type ProcView struct {
	Name string `json:"name"`
	PID  uint32 `json:"pid"`
	Path string `json:"path"`
}

// ListProcesses returns the running processes deduplicated by name (first
// PID wins). PIDs that cannot be opened (System, Idle, protected processes)
// are skipped silently: no path means no reliable app name.
func (c *Controller) ListProcesses() ([]ProcView, error) {
	pids := make([]uint32, 8192) // 32 KB: well past any desktop's process count
	var n uint32
	if err := windows.EnumProcesses(pids, &n); err != nil {
		return nil, err
	}
	// shortcut: a list longer than the buffer is truncated, raise it if a box ever sees >8192 processes
	pids = pids[:n/4]
	out := make([]ProcView, 0, len(pids))
	seen := make(map[string]bool, len(pids))
	buf := make([]uint16, 1024) // long paths (\\?\UNC\…) exceed MAX_PATH
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue
		}
		size := uint32(len(buf))
		err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
		windows.CloseHandle(h)
		if err != nil || size == 0 {
			continue
		}
		path := windows.UTF16ToString(buf[:size])
		name := strings.ToLower(filepath.Base(path))
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, ProcView{Name: name, PID: pid, Path: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
