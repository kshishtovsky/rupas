//go:build windows

// daemon_windows.go — rupasd lifecycle for the GUI (GUI_DESIGN §5 шаг 2, D6):
// discovery + detached spawn (same mechanics as cmd/rupasctl daemon_windows.go)
// + elevation via ShellExecute runas re-launch of ourselves with -startdaemon.
package guictrl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	createNewProcessGroup = 0x00000200
	detachedProcess       = 0x00000008
)

// findDaemon locates rupasd.exe next to the GUI, then in ../build (repo layout).
func findDaemon(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err == nil {
			return override, nil
		}
		return "", fmt.Errorf("rupasd не найден: %s", override)
	}
	var tried []string
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		for _, c := range []string{
			filepath.Join(dir, "rupasd.exe"),
			filepath.Join(dir, "..", "build", "rupasd.exe"),
		} {
			if abs, err := filepath.Abs(c); err == nil {
				c = abs
			}
			tried = append(tried, c)
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c, nil
			}
		}
	}
	return "", fmt.Errorf("rupasd.exe не найден (искал: %v)", tried)
}

// startDaemon spawns rupasd detached with output appended to logPath.
// Returns immediately; the caller polls the pipe.
func startDaemon(daemonPath, configPath, logPath string) error {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("лог %s: %w", logPath, err)
	}
	defer logf.Close()
	cmd := exec.Command(daemonPath, "-config", configPath, "-log", logPath)
	cmd.Stdout = logf
	cmd.Stderr = logf
	if wd := daemonWorkDir(configPath); wd != "" {
		cmd.Dir = wd
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNewProcessGroup | detachedProcess,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск %s: %w", daemonPath, err)
	}
	_ = cmd.Process.Release()
	return nil
}

// daemonWorkDir: repo root when the config lives in <root>/configs/, else the
// config directory (the daemon resolves build/desync and configs relative to it).
func daemonWorkDir(configPath string) string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return ""
	}
	dir := filepath.Dir(abs)
	if filepath.Base(dir) == "configs" {
		return filepath.Dir(dir)
	}
	return dir
}

// EnsureDaemon makes sure rupasd answers on the pipe. It first probes the pipe;
// if silent, it spawns the daemon. When spawning needs elevation (access denied
// or the caller is not admin), it re-launches the GUI binary elevated with
// -startdaemon and waits for the pipe (one UAC prompt, GUI_DESIGN §8).
func (c *Controller) EnsureDaemon() error {
	if _, err := CallPipe(c.opts.Pipe, "status", time.Second); err == nil {
		return nil
	}
	daemonPath, cfg, logPath, err := c.launchSpec()
	if err != nil {
		return err
	}
	if err := startDaemon(daemonPath, cfg, logPath); err != nil {
		// Likely ERROR_ELEVATION_REQUIRED (WinDivert driver) → runas path.
		if elevErr := c.elevatedStartDaemon(daemonPath, cfg, logPath); elevErr != nil {
			return fmt.Errorf("%w; elevated: %v", err, elevErr)
		}
	}
	return waitForPipe(c.opts.Pipe, 15*time.Second)
}

// launchSpec resolves everything needed to spawn the daemon: binary (next to the
// GUI, else ../build), config and log. Shared by EnsureDaemon and the logon task.
func (c *Controller) launchSpec() (daemonPath, cfg, logPath string, err error) {
	daemonPath, err = findDaemon(c.opts.DaemonPath)
	if err != nil {
		return "", "", "", err
	}
	cfg = c.opts.ConfigPath
	if cfg == "" {
		cfg = DefaultConfigPath()
	}
	logPath = c.opts.LogPath
	if logPath == "" {
		logPath = DefaultLogPath()
	}
	return daemonPath, cfg, logPath, nil
}

// DefaultLogPath is where the GUI keeps the daemon log: %LocalAppData%\rupas\
// logs\rupasd.log, the same rotating file rupasd writes on its own when it is
// started without -log. The GUI reads it for the «Подробно» view.
func DefaultLogPath() string {
	dir := os.Getenv("LocalAppData")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "rupas", "logs", "rupasd.log")
}

// waitForPipe polls status until the daemon answers or the deadline passes.
func waitForPipe(pipe string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := CallPipe(pipe, "status", time.Second); err == nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return ErrDaemonDown
}

var (
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteW")
)

// elevatedStartDaemon re-launches the GUI exe with -startdaemon via runas.
func (c *Controller) elevatedStartDaemon(daemonPath, cfg, logPath string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	args := fmt.Sprintf("-startdaemon -daemon %q -config %q -log %q", daemonPath, cfg, logPath)
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(self)
	params, _ := windows.UTF16PtrFromString(args)
	hwnd := windows.Handle(0)
	res, _, _ := procShellExecute.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		0, // dir
		1, // SW_SHOWNORMAL
	)
	if res <= 32 {
		return fmt.Errorf("elevation отклонена (ShellExecute=%d)", res)
	}
	return nil
}

// RunStartDaemonFlag services `-startdaemon` from the elevated relaunch:
// it spawns rupasd and exits.
func (c *Controller) RunStartDaemonFlag(daemonPath, cfg, logPath string) error {
	if daemonPath == "" {
		var err error
		daemonPath, err = findDaemon("")
		if err != nil {
			return err
		}
	}
	return startDaemon(daemonPath, cfg, logPath)
}
