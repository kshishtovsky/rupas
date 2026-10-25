//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Windows process creation flags. DETACHED_PROCESS keeps the daemon alive
// after the TUI exits; CREATE_NEW_PROCESS_GROUP detaches it from the
// console's Ctrl+C so closing the TUI never kills interception.
const (
	createNewProcessGroup = 0x00000200
	detachedProcess       = 0x00000008
)

// daemonCandidates lists where rupasd.exe may live, in priority order:
// next to rupasctl.exe first (installed layout), then the repo build dir,
// then the working directory.
func daemonCandidates() []string {
	var out []string
	if self, err := os.Executable(); err == nil {
		out = append(out, filepath.Join(filepath.Dir(self), "rupasd.exe"))
	}
	out = append(out,
		filepath.Join("build", "rupasd.exe"),
		"rupasd.exe",
	)
	return out
}

// findDaemon returns the first existing rupasd.exe path.
func findDaemon() (string, error) {
	tried := make([]string, 0, 3)
	for _, c := range daemonCandidates() {
		if abs, err := filepath.Abs(c); err == nil {
			c = abs
		}
		tried = append(tried, c)
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("rupasd.exe не найден (искал: %v) — соберите: go build -tags \"with_utls with_quic\" -o build/rupasd.exe ./cmd/rupasd", tried)
}

// startDaemon spawns rupasd detached with its stderr/stdout appended to
// logPath, and returns immediately. The caller polls the control pipe to
// learn when the daemon is actually serving.
func startDaemon(daemonPath, configPath, logPath string) error {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("лог %s: %w", logPath, err)
	}
	defer logf.Close()

	cmd := exec.Command(daemonPath, "-config", configPath)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.Dir = daemonWorkDir(configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNewProcessGroup | detachedProcess,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск %s: %w", daemonPath, err)
	}
	// Release the child: on Windows this just closes our handle, the
	// process keeps running detached.
	_ = cmd.Process.Release()
	return nil
}

// daemonWorkDir picks the daemon's working directory: the repo root when
// the config lives in <root>/configs/, else the current directory. The
// daemon resolves build/desync/* and configs/* relative to it.
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

// waitForDaemon polls the control pipe until the daemon answers or the
// deadline passes.
func waitForDaemon(pipePath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if _, err := rpcCommand(pipePath, "status", 1500*time.Millisecond); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return fmt.Errorf("демон не поднялся за %s: %v", timeout, last)
}

// startDaemonCmd is the `rupasctl start` implementation: spawn rupasd
// detached, wait for the control pipe, report honestly.
func startDaemonCmd(configPath, pipePath string) error {
	if _, err := rpcCommand(pipePath, "status", 1500*time.Millisecond); err == nil {
		fmt.Println("rupasd уже запущен")
		return nil
	}
	daemonPath, err := findDaemon()
	if err != nil {
		return err
	}
	logPath := filepath.Join(daemonWorkDir(configPath), "build", "rupasd-tui.log")
	if err := startDaemon(daemonPath, configPath, logPath); err != nil {
		return err
	}
	if err := waitForDaemon(pipePath, 20*time.Second); err != nil {
		if tail := tailLog(logPath, 6); tail != "" {
			return fmt.Errorf("%v\nпоследние строки %s:\n%s", err, logPath, tail)
		}
		return err
	}
	fmt.Printf("rupasd запущен (pid отдельный, лог: %s)\n", logPath)
	return nil
}

// tailLog returns the last n lines of path (best effort, for surfacing a
// failed daemon start without leaving the TUI).
func tailLog(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	lines := make([]string, 0, n)
	start := len(data)
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' {
			if start > i+1 {
				lines = append(lines, string(data[i+1:start]))
				if len(lines) >= n {
					break
				}
			}
			start = i
		}
	}
	// Reverse into chronological order.
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}
