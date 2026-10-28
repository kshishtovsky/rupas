package main

// TUI support: config persistence (validate → backup → atomic write →
// RPC reload → rollback), RPC polling helpers and the TTY guard.
//
// The daemon-facing part is deliberately thin: rupasctl already knows how
// to speak the JSON-line protocol (main.go); the TUI reuses DialPipe for
// single-shot commands and polls `status` on a ticker.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/core"
	"github.com/kshishtovsky/rupas/internal/rpc"
	"gopkg.in/yaml.v3"
)

// statusInterval is the Status-tab polling period.
const statusInterval = 2 * time.Second

// errNoDaemon marks "daemon unreachable" so callers can badge the UI
// instead of failing: the TUI must stay usable for config editing while
// rupasd is down.
var errNoDaemon = errors.New("daemon offline")

// statusFetcher is the seam used by tests: it performs one RPC call and
// returns (snapshot, err). The real implementation is rpcFetchSnapshot.
type statusFetcher func(pipePath string, timeout time.Duration) (core.Snapshot, error)

// runTUI is the `rupasctl tui` entry point: refuses non-TTY stdin (so a
// cron job or a pipe gets a clean hint instead of a bubbletea panic),
// loads the config (best effort — an invalid file must still be openable
// in the editor so the user can fix it), then hands over to bubbletea.
func runTUI(configPath, pipePath string, timeout time.Duration) error {
	if !isTerminal(os.Stdin) {
		return errors.New("tui: stdin is not a terminal — запустите rupasctl tui в интерактивной консоли (PowerShell / Windows Terminal)")
	}

	m := newTUIModel(configPath, pipePath, timeout, rpcFetchSnapshot)
	if _, err := m.loadConfigFromDisk(); err != nil {
		// Keep going: the editor opens with an empty model and a
		// warning; `s` will refuse to write until the config
		// validates (which requires re-entering the broken parts).
		m.statusMsg = "конфиг не читается: " + err.Error() + " — редактор открыт с пустой моделью"
		m.cfgLoaded = false
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// isTerminal reports whether f is attached to a character device.
// Done without x/term to keep the dependency footprint small.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// rpcFetchSnapshot is the real statusFetcher: one `status` round-trip.
func rpcFetchSnapshot(pipePath string, timeout time.Duration) (core.Snapshot, error) {
	res, err := rpcCommand(pipePath, "status", timeout)
	if err != nil {
		return core.Snapshot{}, err
	}
	return res.snapshot, nil
}

// rpcResult bundles the payload shapes the TUI consumes.
type rpcResult struct {
	snapshot core.Snapshot
	ok       bool
}

// rpcCommand performs one JSON-line RPC request and decodes the reply.
// A transport failure maps to errNoDaemon so the UI can badge it honestly.
func rpcCommand(pipePath, cmd string, timeout time.Duration) (rpcResult, error) {
	conn, err := rpc.DialPipe(pipePath, timeout)
	if err != nil {
		return rpcResult{}, fmt.Errorf("%w: %v", errNoDaemon, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req, _ := json.Marshal(rpc.Request{Cmd: cmd})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return rpcResult{}, fmt.Errorf("%w: write: %v", errNoDaemon, err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return rpcResult{}, fmt.Errorf("%w: read: %v", errNoDaemon, err)
	}
	var r struct {
		OK    bool          `json:"ok"`
		Data  core.Snapshot `json:"data"`
		Error string        `json:"error"`
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return rpcResult{}, fmt.Errorf("bad response: %w", err)
	}
	if !r.OK {
		return rpcResult{}, errors.New(r.Error)
	}
	return rpcResult{snapshot: r.Data, ok: true}, nil
}

// rpcAction sends a fire-and-forget command (on/off/probe/reload) and
// returns the daemon-side or transport error, if any.
func rpcAction(pipePath, cmd string, timeout time.Duration) error {
	_, err := rpcCommand(pipePath, cmd, timeout)
	return err
}

// buildConfigYAML renders the TUI model back into the config.Config tree.
// Everything the TUI does not manage (profile, exclusions) is carried over
// from the on-disk config so a save never silently drops it.
func buildConfigYAML(m tuiModel) config.Config {
	cfg := m.baseConfig // zero value when the disk config was unreadable
	cfg.Rules = append([]config.Rule(nil), m.rules...)
	cfg.Desync = m.desync
	tun := m.tunnels.toTunnelConfig()
	if tun.Configured() {
		cfg.Tunnels = &tun
	} else {
		cfg.Tunnels = nil
	}
	// A stale legacy `tunnel:` section must never resurrect: if the user
	// clears all endpoints while a legacy block exists on disk, prefer
	// dropping it over an ambiguous both-set config (Validate rejects
	// that combination outright).
	if !tun.Configured() {
		cfg.Tunnel = config.TunnelEndpoint{}
	}
	return cfg
}

// writeValidated renders cfg to YAML and validates it with the real engine
// by round-tripping through a temporary file — exactly what `s` does before
// touching the live config. Returns the rendered bytes so the caller does
// not re-marshal (and cannot diverge from what was validated).
func writeValidated(cfg config.Config, workDir string) ([]byte, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	tmp, err := os.CreateTemp(workDir, "rupas-validate-*.yaml")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if _, err := config.Load(tmpName); err != nil {
		return nil, err
	}
	return data, nil
}

// saveConfigFile is the full save pipeline:
//
//  1. marshal + validate via a temp file (config.Load — the real engine)
//  2. back up the existing file to <name>.bak
//  3. atomically replace the file (write temp → rename in the same dir)
//  4. ask the daemon to reload; on failure restore the backup and report
//     «откатено»
//
// reloadFn is injectable for tests. backupPath is "" when there was nothing
// to back up (first save). The returned error is user-facing Russian text.
func saveConfigFile(m *tuiModel, reloadFn func() error) (backupPath string, err error) {
	cfg := buildConfigYAML(*m)
	dir := filepath.Dir(m.configPath)

	data, err := writeValidated(cfg, dir)
	if err != nil {
		return "", fmt.Errorf("валидация не прошла, файл не изменён: %w", err)
	}

	// Backup: keep the previous bytes exactly as they were.
	if _, statErr := os.Stat(m.configPath); statErr == nil {
		backupPath = m.configPath + ".bak"
		if b, rErr := os.ReadFile(m.configPath); rErr == nil {
			if wErr := os.WriteFile(backupPath, b, 0o600); wErr != nil {
				return "", fmt.Errorf("не удалось создать backup %s: %w", backupPath, wErr)
			}
		} else {
			return "", fmt.Errorf("не удалось прочитать %s для backup: %w", m.configPath, rErr)
		}
	}

	// Atomic replace: same directory → same volume → rename is atomic.
	tmp, err := os.CreateTemp(dir, "rupas-save-*.yaml")
	if err != nil {
		return backupPath, fmt.Errorf("не удалось создать временный файл: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return backupPath, fmt.Errorf("запись временного файла: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return backupPath, fmt.Errorf("закрытие временного файла: %w", err)
	}
	if err := os.Rename(tmpName, m.configPath); err != nil {
		os.Remove(tmpName)
		return backupPath, fmt.Errorf("атомарная замена %s: %w", m.configPath, err)
	}

	// Hand the new config to the daemon. Any reload failure rolls the
	// file back: the daemon must never run stale while the disk holds a
	// config it refused.
	if reloadFn != nil {
		if rErr := reloadFn(); rErr != nil {
			if backupPath != "" {
				if b, readErr := os.ReadFile(backupPath); readErr == nil {
					_ = os.WriteFile(m.configPath, b, 0o600)
				}
			} else {
				// First save: no previous file existed; remove ours.
				_ = os.Remove(m.configPath)
			}
			return backupPath, fmt.Errorf("reload отклонён, откатено на предыдущий конфиг: %v", rErr)
		}
	}
	return backupPath, nil
}

// restoreBackup copies <path>.bak back over path (used by tests and by the
// manual rollback hint in the footer). Reports whether it restored.
func restoreBackup(path string) bool {
	b, err := os.ReadFile(path + ".bak")
	if err != nil {
		return false
	}
	return os.WriteFile(path, b, 0o600) == nil
}

// rpcTickMsg is the timer half of the status polling loop.
type rpcTickMsg time.Time

// fetchedMsg carries a completed snapshot fetch to Update.
type fetchedMsg struct {
	snap core.Snapshot
	err  error
}

// actionResultMsg carries the outcome of on/off/probe/reload/save.
type actionResultMsg struct {
	label string
	err   error
}

// pollTick schedules the next status poll.
func pollTick() tea.Cmd {
	return tea.Tick(statusInterval, func(t time.Time) tea.Msg {
		return rpcTickMsg(t)
	})
}

// fetchStatusCmd performs one snapshot fetch off the UI goroutine.
func fetchStatusCmd(m tuiModel) tea.Cmd {
	pipe, timeout := m.pipePath, m.rpcTimeout
	return func() tea.Msg {
		snap, err := m.fetch(pipe, timeout)
		return fetchedMsg{snap: snap, err: err}
	}
}
