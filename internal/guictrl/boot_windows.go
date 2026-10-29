//go:build windows

// boot_windows.go — login restore. The Run entry starts the GUI and the logon
// task starts the daemon, both without user action, so boot only has to wait
// for the pipe and re-apply the interception state the user left behind.
package guictrl

import (
	"os"
	"path/filepath"
	"time"
)

func wantOnPath() string { return filepath.Join(stateDir(), "active.flag") }

// wantOn reports the state the user left behind (set by On, cleared by Off).
func wantOn() bool {
	_, err := os.Stat(wantOnPath())
	return err == nil
}

func writeWantOn(on bool) error {
	if !on {
		if err := os.Remove(wantOnPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(wantOnPath(), []byte("on"), 0o600)
}

// AutoStart is the GUI's boot hook: it restores interception after a reboot
// when it was on before shutdown. The logon task brings the daemon up in
// parallel, so it waits for the pipe first and only spawns when the task is
// missing (one UAC prompt, as any manual start).
func (c *Controller) AutoStart() error {
	if !wantOn() {
		return nil
	}
	if err := waitForPipe(c.opts.Pipe, 20*time.Second); err != nil {
		if err := c.EnsureDaemon(); err != nil {
			return err
		}
	}
	return c.On()
}
