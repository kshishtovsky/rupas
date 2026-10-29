//go:build !windows

// procs_other.go — the process picker exists off Windows only as an empty
// list: app rules are validated but never matched without socket attribution
// (PLAN-0.8 §1.1).
package guictrl

// ProcView is one picker row: Name is what a rule stores (basename,
// lower-case), Path is shown as the hint.
type ProcView struct {
	Name string `json:"name"`
	PID  uint32 `json:"pid"`
	Path string `json:"path"`
}

// ListProcesses returns no processes off Windows (never nil: the UI maps it).
func (c *Controller) ListProcesses() ([]ProcView, error) { return []ProcView{}, nil }
