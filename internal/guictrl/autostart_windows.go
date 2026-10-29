//go:build windows

// autostart_windows.go — login autostart: the HKCU Run entry starts the
// non-elevated GUI, and the "Rupas daemon" logon task starts rupasd elevated
// (WinDivert needs admin), so a reboot does not depend on a UAC click.
package guictrl

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = "Rupas"

// taskName is the elevated logon task that spawns rupasd.
const taskName = "Rupas daemon"

// Autostart reports whether the GUI launches at login.
func (c *Controller) Autostart() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValueName)
	return err == nil
}

// RepairAutostart re-points a stale Run entry (and its logon task) at the
// running binary: the entry is written once, so a rebuild into a new path would
// otherwise launch a deleted exe at every login.
func (c *Controller) RepairAutostart() error {
	if !c.Autostart() {
		return nil
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, _, err := k.GetStringValue(runValueName)
	if err != nil {
		return err
	}
	want := `"` + selfPath() + `"`
	if cur == want {
		return nil
	}
	if err := k.SetStringValue(runValueName, want); err != nil {
		return err
	}
	return c.syncDaemonTask(true)
}

// SetAutostart adds or removes the GUI Run entry and the daemon logon task.
func (c *Controller) SetAutostart(on bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("autostart: %w", err)
	}
	defer k.Close()
	if on {
		if err := k.SetStringValue(runValueName, `"`+selfPath()+`"`); err != nil {
			return fmt.Errorf("autostart: %w", err)
		}
	} else if err := k.DeleteValue(runValueName); err != nil {
		return fmt.Errorf("autostart: %w", err)
	}
	return c.syncDaemonTask(on)
}

// syncDaemonTask creates or removes the logon task. schtasks needs no elevation
// for the current user's own HighestAvailable task, so the GUI stays unelevated.
func (c *Controller) syncDaemonTask(on bool) error {
	if !on {
		// A missing task is the desired state.
		_, _ = runSchtasks("/Delete", "/TN", taskName, "/F")
		return nil
	}
	daemonPath, cfg, logPath, err := c.launchSpec()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" -startdaemon -daemon "%s" -config "%s" -log "%s"`,
		selfPath(), daemonPath, cfg, logPath)
	_, err = runSchtasks("/Create", "/TN", taskName, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F", "/TR", tr)
	return err
}

func runSchtasks(args ...string) (string, error) {
	cmd := exec.Command("schtasks", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("schtasks %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
