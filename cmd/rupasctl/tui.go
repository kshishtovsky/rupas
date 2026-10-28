package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/core"
	"gopkg.in/yaml.v3"
)

// tab identifiers.
type tab int

const (
	tabStatus tab = iota
	tabRules
	tabDesync
	tabTunnels
	tabCount = 4
)

func (t tab) name() string {
	switch t {
	case tabStatus:
		return "1:Статус"
	case tabRules:
		return "2:Правила"
	case tabDesync:
		return "3:Desync"
	case tabTunnels:
		return "4:Туннели"
	}
	return ""
}

// editMode marks in-flight modals / sub-editors.
type editMode int

const (
	editNone editMode = iota
	editRuleWizard
	editConfirmDelete
	editTunnelSecret
)

// tunnelModel wraps the 3 endpoints + chain flag and satisfies toTunnelConfig().
type tunnelModel struct {
	tcp                  *config.Endpoint
	udp                  *config.Endpoint
	fallback             *config.Endpoint
	xhttpFallbackInChain bool
}

func (tm tunnelModel) toTunnelConfig() config.TunnelConfig {
	return config.TunnelConfig{
		TCP:                  tm.tcp,
		UDP:                  tm.udp,
		Fallback:             tm.fallback,
		XHTTPFallbackInChain: tm.xhttpFallbackInChain,
	}
}

// tuiModel is the root bubbletea model for `rupasctl tui`.
type tuiModel struct {
	configPath string
	pipePath   string
	rpcTimeout time.Duration
	fetch      statusFetcher

	// Window
	width  int
	height int

	// Active tab
	activeTab tab

	// Base config loaded from disk (perserves unmanaged fields like profile, exclusions)
	baseConfig config.Config

	// Global flash/status message (shown in the footer)
	statusMsg   string
	statusIsErr bool
	cfgLoaded   bool
	dirty       bool

	// Tab 1: Status
	snap      core.Snapshot
	daemonErr error
	lastPoll  time.Time

	// Tab 2: Rules
	rules    []config.Rule
	ruleSel  int
	edit     editMode
	editNew  bool // true = add, false = edit
	editStep int  // 0 matcher type, 1 value, 2 proto, 3 action
	wizType  int  // 0 cidr, 1 sni, 2 ports, 3 default
	wizProto int  // 0 any, 1 tcp, 2 udp
	wizAct   int  // 0 direct, 1 desync, 2 tunnel, 3 block
	wizInput textinput.Model
	wizErr   string

	// Tab 3: Desync
	desync       config.DesyncParams
	desyncFocus  int // 0..5
	desyncInputs [6]textinput.Model

	// Tab 4: Tunnels
	tunnels     tunnelModel
	tunEndpoint int // 0 tcp, 1 udp, 2 fallback
	tunField    int // 0 kind, 1 host, 2 port, 3 uuid, 4 pass, 5 sni, 6 alpn, 7 fp, 8 path
	tunSecretIn textinput.Model
}

func newTUIModel(configPath, pipePath string, timeout time.Duration, fetch statusFetcher) tuiModel {
	m := tuiModel{
		configPath: configPath,
		pipePath:   pipePath,
		rpcTimeout: timeout,
		fetch:      fetch,
		activeTab:  tabStatus,
	}

	ti := textinput.New()
	ti.Prompt = "> "
	ti.CharLimit = 256
	m.wizInput = ti

	labels := []string{"Strategy", "FakeTemplate", "TTL", "TTLMargin", "Repeats", "SplitOffset"}
	for i := 0; i < len(m.desyncInputs); i++ {
		inp := textinput.New()
		inp.Prompt = labels[i] + ": "
		inp.CharLimit = 128
		m.desyncInputs[i] = inp
	}

	sinp := textinput.New()
	sinp.Prompt = "Новый секрет: "
	sinp.EchoMode = textinput.EchoPassword
	sinp.CharLimit = 128
	m.tunSecretIn = sinp

	return m
}

func (m *tuiModel) loadConfigFromDisk() (bool, error) {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return false, err
	}
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return false, err
	}
	m.baseConfig = cfg
	m.rules = cfg.Rules
	m.desync = cfg.Desync

	if cfg.Tunnels != nil {
		m.tunnels = tunnelModel{
			tcp:                  cfg.Tunnels.TCP,
			udp:                  cfg.Tunnels.UDP,
			fallback:             cfg.Tunnels.Fallback,
			xhttpFallbackInChain: cfg.Tunnels.XHTTPFallbackInChain,
		}
	}

	m.desyncInputs[0].SetValue(cfg.Desync.Strategy)
	m.desyncInputs[1].SetValue(cfg.Desync.FakeTemplate)
	m.desyncInputs[2].SetValue(strconv.Itoa(cfg.Desync.TTL))
	m.desyncInputs[3].SetValue(strconv.Itoa(cfg.Desync.TTLMargin))
	m.desyncInputs[4].SetValue(strconv.Itoa(cfg.Desync.Repeats))
	m.desyncInputs[5].SetValue(strconv.Itoa(cfg.Desync.SplitOffset))

	m.cfgLoaded = true
	m.dirty = false
	return true, nil
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		fetchStatusCmd(m),
		pollTick(),
	)
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case rpcTickMsg:
		if m.activeTab == tabStatus {
			return m, tea.Batch(fetchStatusCmd(m), pollTick())
		}
		return m, pollTick()

	case fetchedMsg:
		m.snap = msg.snap
		m.daemonErr = msg.err
		m.lastPoll = time.Now()
		return m, nil

	case actionResultMsg:
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("[%s ошибка]: %v", msg.label, msg.err)
			m.statusIsErr = true
		} else {
			m.statusMsg = fmt.Sprintf("[%s]: успешно", msg.label)
			m.statusIsErr = false
		}
		return m, nil

	case daemonStartMsg:
		if msg.err != nil {
			m.statusMsg = "ОШИБКА запуска демона: " + msg.err.Error()
			m.statusIsErr = true
			return m, nil
		}
		m.statusMsg = "демон запущен"
		m.statusIsErr = false
		return m, fetchStatusCmd(m)

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}

		if m.edit != editNone {
			return m.handleModalKey(msg)
		}

		if msg.String() == "s" && m.activeTab != tabStatus {
			return m.handleSave()
		}

		switch msg.String() {
		case "1":
			m.activeTab = tabStatus
			return m, fetchStatusCmd(m)
		case "2":
			m.activeTab = tabRules
			return m, nil
		case "3":
			m.activeTab = tabDesync
			return m, nil
		case "4":
			m.activeTab = tabTunnels
			return m, nil
		case "tab":
			m.activeTab = (m.activeTab + 1) % tabCount
			if m.activeTab == tabStatus {
				return m, fetchStatusCmd(m)
			}
			return m, nil
		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + tabCount) % tabCount
			if m.activeTab == tabStatus {
				return m, fetchStatusCmd(m)
			}
			return m, nil
		case "q":
			return m, tea.Quit
		}

		switch m.activeTab {
		case tabStatus:
			return m.handleStatusKey(msg)
		case tabRules:
			return m.handleRulesKey(msg)
		case tabDesync:
			return m.handleDesyncKey(msg)
		case tabTunnels:
			return m.handleTunnelsKey(msg)
		}
	}

	return m, nil
}

func (m tuiModel) handleSave() (tea.Model, tea.Cmd) {
	m.statusMsg = "сохранение..."
	m.statusIsErr = false

	// Sync desyncInputs -> m.desync before building config
	ttl, _ := strconv.Atoi(strings.TrimSpace(m.desyncInputs[2].Value()))
	margin, _ := strconv.Atoi(strings.TrimSpace(m.desyncInputs[3].Value()))
	rep, _ := strconv.Atoi(strings.TrimSpace(m.desyncInputs[4].Value()))
	split, _ := strconv.Atoi(strings.TrimSpace(m.desyncInputs[5].Value()))
	m.desync = config.DesyncParams{
		Strategy:     strings.TrimSpace(m.desyncInputs[0].Value()),
		FakeTemplate: strings.TrimSpace(m.desyncInputs[1].Value()),
		TTL:          ttl,
		TTLMargin:    margin,
		Repeats:      rep,
		SplitOffset:  split,
	}

	pipe, timeout := m.pipePath, m.rpcTimeout
	daemonWasOffline := false
	reloadFn := func() error {
		res, err := rpcCommand(pipe, "reload", timeout)
		if err != nil {
			if errors.Is(err, errNoDaemon) {
				daemonWasOffline = true
				return nil // Don't rollback: config is already validated, daemon is just offline
			}
			return err
		}
		if !res.ok {
			return fmt.Errorf("daemon отклонил reload")
		}
		return nil
	}

	bak, err := saveConfigFile(&m, reloadFn)
	if err != nil {
		m.statusMsg = "ОШИБКА: " + err.Error()
		m.statusIsErr = true
		return m, nil
	}
	m.dirty = false
	if daemonWasOffline {
		m.statusMsg = "сохранено на диск (демон оффлайн, reload пропущен)"
	} else if bak != "" {
		m.statusMsg = fmt.Sprintf("сохранено и reload выполнен (бэкап: %s)", bak)
	} else {
		m.statusMsg = "сохранено и reload выполнен"
	}
	return m, nil
}

// -------------------------------------------------------------
// TAB 1: STATUS
// -------------------------------------------------------------

// daemonStartMsg reports the outcome of spawning rupasd from the TUI.
type daemonStartMsg struct {
	err error
}

// startDaemonThen spawns rupasd (detached), waits for the control pipe and
// then optionally runs followUp ("on", "probe", ...). All of it happens off
// the UI goroutine so the TUI stays responsive.
func (m tuiModel) startDaemonThen(followUp string) (tea.Model, tea.Cmd) {
	m.statusMsg = "запускаю демон..."
	m.statusIsErr = false

	configPath := m.configPath
	pipe, timeout := m.pipePath, m.rpcTimeout
	daemonPath, err := findDaemon()
	if err != nil {
		m.statusMsg = "ОШИБКА: " + err.Error()
		m.statusIsErr = true
		return m, nil
	}
	logPath := filepath.Join(daemonWorkDir(configPath), "build", "rupasd-tui.log")

	return m, func() tea.Msg {
		if err := startDaemon(daemonPath, configPath, logPath); err != nil {
			return daemonStartMsg{err: err}
		}
		if err := waitForDaemon(pipe, 20*time.Second); err != nil {
			if tail := tailLog(logPath, 6); tail != "" {
				return daemonStartMsg{err: fmt.Errorf("%v\nпоследние строки %s:\n%s", err, logPath, tail)}
			}
			return daemonStartMsg{err: err}
		}
		if followUp != "" {
			if _, err := rpcCommand(pipe, followUp, timeout); err != nil {
				return daemonStartMsg{err: err}
			}
		}
		return daemonStartMsg{}
	}
}

func (m tuiModel) handleStatusKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pipe, timeout := m.pipePath, m.rpcTimeout
	switch msg.String() {
	case "o":
		if m.daemonErr != nil {
			return m.startDaemonThen("on")
		}
		return m, func() tea.Msg {
			_, err := rpcCommand(pipe, "on", timeout)
			return actionResultMsg{label: "on", err: err}
		}
	case "D":
		if m.daemonErr == nil {
			m.statusMsg = "демон уже запущен"
			return m, nil
		}
		return m.startDaemonThen("")
	case "f":
		return m, func() tea.Msg {
			_, err := rpcCommand(pipe, "off", timeout)
			return actionResultMsg{label: "off", err: err}
		}
	case "p":
		return m, func() tea.Msg {
			_, err := rpcCommand(pipe, "probe", timeout)
			return actionResultMsg{label: "probe", err: err}
		}
	case "r":
		return m, fetchStatusCmd(m)
	}
	return m, nil
}

// -------------------------------------------------------------
// TAB 2: RULES
// -------------------------------------------------------------

func (m tuiModel) handleRulesKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	n := len(m.rules)
	switch msg.String() {
	case "up", "k":
		if m.ruleSel > 0 {
			m.ruleSel--
		}
	case "down", "j":
		if m.ruleSel < n-1 {
			m.ruleSel++
		}
	case "n":
		m.edit = editRuleWizard
		m.editNew = true
		m.editStep = 0
		m.wizType = 1 // SNI
		m.wizProto = 0
		m.wizAct = 2 // tunnel
		m.wizErr = ""
		m.wizInput.Reset()
		m.wizInput.Focus()
	case "e":
		if n == 0 || m.ruleSel >= n {
			return m, nil
		}
		r := m.rules[m.ruleSel]
		if r.GeoIP != "" {
			// The wizard has no geoip matcher: committing would rebuild the
			// rule as a matcher-less DEFAULT and silently turn a scoped
			// geoip rule into a catch-all.
			m.statusMsg = "geoip-правило правится только в YAML (визард не умеет geoip)"
			m.statusIsErr = true
			return m, nil
		}
		m.edit = editRuleWizard
		m.editNew = false
		m.editStep = 0
		m.wizErr = ""
		if r.CIDR != "" {
			m.wizType = 0
			m.wizInput.SetValue(r.CIDR)
		} else if r.SNI != "" {
			m.wizType = 1
			m.wizInput.SetValue(r.SNI)
		} else if r.Ports != "" {
			m.wizType = 2
			m.wizInput.SetValue(r.Ports)
		} else {
			m.wizType = 3
			m.wizInput.Reset()
		}
		switch strings.ToLower(r.Proto) {
		case "tcp":
			m.wizProto = 1
		case "udp":
			m.wizProto = 2
		default:
			m.wizProto = 0
		}
		switch r.Action {
		case config.ActionDirect:
			m.wizAct = 0
		case config.ActionDesync:
			m.wizAct = 1
		case config.ActionTunnel:
			m.wizAct = 2
		case config.ActionBlock:
			m.wizAct = 3
		}
		m.wizInput.Focus()
	case "d":
		if n > 0 && m.ruleSel < n {
			r := m.rules[m.ruleSel]
			if r.CIDR == "" && r.SNI == "" && r.Ports == "" && r.GeoIP == "" {
				m.statusMsg = "дефолтное правило нельзя удалить"
				m.statusIsErr = true
				return m, nil
			}
			m.edit = editConfirmDelete
		}
	case "K", "ctrl+up":
		if m.ruleSel > 0 && m.ruleSel < n {
			m.rules[m.ruleSel-1], m.rules[m.ruleSel] = m.rules[m.ruleSel], m.rules[m.ruleSel-1]
			m.ruleSel--
			m.dirty = true
		}
	case "J", "ctrl+down":
		if m.ruleSel >= 0 && m.ruleSel < n-1 {
			m.rules[m.ruleSel], m.rules[m.ruleSel+1] = m.rules[m.ruleSel+1], m.rules[m.ruleSel]
			m.ruleSel++
			m.dirty = true
		}
	}
	return m, nil
}

// -------------------------------------------------------------
// TAB 3: DESYNC
// -------------------------------------------------------------

func (m tuiModel) handleDesyncKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "shift+tab":
		m.desyncInputs[m.desyncFocus].Blur()
		m.desyncFocus = (m.desyncFocus - 1 + len(m.desyncInputs)) % len(m.desyncInputs)
		m.desyncInputs[m.desyncFocus].Focus()
		return m, nil
	case "down", "enter":
		m.desyncInputs[m.desyncFocus].Blur()
		m.desyncFocus = (m.desyncFocus + 1) % len(m.desyncInputs)
		m.desyncInputs[m.desyncFocus].Focus()
		return m, nil
	}

	var cmd tea.Cmd
	m.desyncInputs[m.desyncFocus], cmd = m.desyncInputs[m.desyncFocus].Update(msg)
	m.dirty = true
	return m, cmd
}

// -------------------------------------------------------------
// TAB 4: TUNNELS
// -------------------------------------------------------------

func (m tuiModel) handleTunnelsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h":
		if m.tunEndpoint > 0 {
			m.tunEndpoint--
		}
	case "right", "l":
		if m.tunEndpoint < 2 {
			m.tunEndpoint++
		}
	case "up", "k":
		if m.tunField > 0 {
			m.tunField--
		}
	case "down", "j":
		if m.tunField < 8 {
			m.tunField++
		}
	case "x":
		m.tunnels.xhttpFallbackInChain = !m.tunnels.xhttpFallbackInChain
		m.dirty = true
		m.statusMsg = fmt.Sprintf("xhttp_fallback_in_chain: %v", m.tunnels.xhttpFallbackInChain)
	case "e":
		if m.tunField == 3 || m.tunField == 4 {
			m.edit = editTunnelSecret
			m.tunSecretIn.Reset()
			m.tunSecretIn.Focus()
		}
	}
	return m, nil
}

// -------------------------------------------------------------
// MODALS / SUB-EDITORS
// -------------------------------------------------------------

func (m tuiModel) handleModalKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.edit {
	case editConfirmDelete:
		switch msg.String() {
		case "y", "Y", "enter":
			if m.ruleSel >= 0 && m.ruleSel < len(m.rules) {
				m.rules = append(m.rules[:m.ruleSel], m.rules[m.ruleSel+1:]...)
				if m.ruleSel >= len(m.rules) && m.ruleSel > 0 {
					m.ruleSel--
				}
				m.dirty = true
				m.statusMsg = "правило удалено (нажмите s для сохранения)"
				m.statusIsErr = false
			}
			m.edit = editNone
		case "n", "N", "esc", "q":
			m.edit = editNone
		}
		return m, nil

	case editTunnelSecret:
		switch msg.String() {
		case "esc":
			m.edit = editNone
			return m, nil
		case "enter":
			val := strings.TrimSpace(m.tunSecretIn.Value())
			if val != "" {
				ep := m.getEndpoint(m.tunEndpoint)
				if ep != nil {
					if m.tunField == 3 {
						ep.UUID = val
					} else if m.tunField == 4 {
						ep.Password = val
					}
					m.dirty = true
					m.statusMsg = "секрет обновлён"
				}
			}
			m.edit = editNone
			return m, nil
		}
		var cmd tea.Cmd
		m.tunSecretIn, cmd = m.tunSecretIn.Update(msg)
		return m, cmd

	case editRuleWizard:
		return m.handleWizardKey(msg)
	}

	return m, nil
}

func (m *tuiModel) getEndpoint(idx int) *config.Endpoint {
	switch idx {
	case 0:
		if m.tunnels.tcp == nil {
			m.tunnels.tcp = &config.Endpoint{}
		}
		return m.tunnels.tcp
	case 1:
		if m.tunnels.udp == nil {
			m.tunnels.udp = &config.Endpoint{}
		}
		return m.tunnels.udp
	case 2:
		if m.tunnels.fallback == nil {
			m.tunnels.fallback = &config.Endpoint{}
		}
		return m.tunnels.fallback
	}
	return nil
}

func (m tuiModel) handleWizardKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.edit = editNone
		return m, nil
	}

	switch m.editStep {
	case 0: // Matcher type
		switch msg.String() {
		case "left", "h":
			if m.wizType > 0 {
				m.wizType--
			}
		case "right", "l":
			if m.wizType < 3 {
				m.wizType++
			}
		case "enter":
			if m.wizType == 3 {
				m.editStep = 3
			} else {
				m.editStep = 1
			}
		}
		return m, nil

	case 1: // Value
		if msg.String() == "enter" {
			val := strings.TrimSpace(m.wizInput.Value())
			switch m.wizType {
			case 0: // CIDR
				if _, _, err := net.ParseCIDR(val); err != nil {
					if net.ParseIP(val) == nil {
						m.wizErr = "неверный CIDR или IP (напр: 1.2.3.0/24)"
						return m, nil
					}
				}
			case 1: // SNI
				if val == "" || strings.Contains(val, " ") {
					m.wizErr = "неверный SNI (напр: *.youtube.com или discord.com)"
					return m, nil
				}
			case 2: // Ports
				if val == "" {
					m.wizErr = "укажите порты (напр: 80,443 или 50000-50010)"
					return m, nil
				}
			}
			m.wizErr = ""
			m.editStep = 2
			return m, nil
		}
		var cmd tea.Cmd
		m.wizInput, cmd = m.wizInput.Update(msg)
		return m, cmd

	case 2: // Proto (any / tcp / udp)
		switch msg.String() {
		case "left", "h":
			if m.wizProto > 0 {
				m.wizProto--
			}
		case "right", "l":
			if m.wizProto < 2 {
				m.wizProto++
			}
		case "enter":
			m.editStep = 3
		}
		return m, nil

	case 3: // Action (direct / desync / tunnel / block)
		switch msg.String() {
		case "left", "h":
			if m.wizAct > 0 {
				m.wizAct--
			}
		case "right", "l":
			if m.wizAct < 3 {
				m.wizAct++
			}
		case "enter":
			r := config.Rule{}
			switch m.wizType {
			case 0:
				r.CIDR = strings.TrimSpace(m.wizInput.Value())
			case 1:
				r.SNI = strings.ToLower(strings.TrimSpace(m.wizInput.Value()))
			case 2:
				r.Ports = strings.TrimSpace(m.wizInput.Value())
			}
			switch m.wizProto {
			case 1:
				r.Proto = "tcp"
			case 2:
				r.Proto = "udp"
			}
			switch m.wizAct {
			case 0:
				r.Action = config.ActionDirect
			case 1:
				r.Action = config.ActionDesync
			case 2:
				r.Action = config.ActionTunnel
			case 3:
				r.Action = config.ActionBlock
			}

			if m.editNew {
				if len(m.rules) > 0 {
					lastIdx := len(m.rules) - 1
					m.rules = append(m.rules[:lastIdx], append([]config.Rule{r}, m.rules[lastIdx:]...)...)
					m.ruleSel = lastIdx
				} else {
					m.rules = append(m.rules, r)
					m.ruleSel = 0
				}
				m.statusMsg = "правило добавлено"
			} else {
				if m.ruleSel >= 0 && m.ruleSel < len(m.rules) {
					m.rules[m.ruleSel] = r
					m.statusMsg = "правило обновлено"
				}
			}
			m.dirty = true
			m.edit = editNone
			return m, nil
		}
		return m, nil
	}

	return m, nil
}

// -------------------------------------------------------------
// VIEW RENDERING
// -------------------------------------------------------------

var (
	tabStyle       = lipgloss.NewStyle().Padding(0, 2).Foreground(lipgloss.Color("240"))
	activeTabStyle = lipgloss.NewStyle().Padding(0, 2).Bold(true).Foreground(lipgloss.Color("255")).Background(lipgloss.Color("63"))
	headerStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	boldStyle      = lipgloss.NewStyle().Bold(true)
	errStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	okStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	subtleStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	selRowStyle    = lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("229")).Bold(true)
	boxStyle       = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
)

func (m tuiModel) View() string {
	var b strings.Builder

	var tabs []string
	for i := 0; i < tabCount; i++ {
		t := tab(i)
		if t == m.activeTab {
			tabs = append(tabs, activeTabStyle.Render(t.name()))
		} else {
			tabs = append(tabs, tabStyle.Render(t.name()))
		}
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, tabs...))
	b.WriteString("\n\n")

	var content string
	switch m.activeTab {
	case tabStatus:
		content = m.renderStatus()
	case tabRules:
		content = m.renderRules()
	case tabDesync:
		content = m.renderDesync()
	case tabTunnels:
		content = m.renderTunnels()
	}
	b.WriteString(content)
	b.WriteString("\n")

	if m.edit != editNone {
		b.WriteString("\n" + m.renderModal() + "\n")
	}

	b.WriteString("\n" + m.renderFooter())

	return b.String()
}

func (m tuiModel) renderStatus() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Состояние демона Rupas") + "\n\n")

	if m.daemonErr != nil {
		b.WriteString(errStyle.Render("● ДЕМОН НЕДОСТУПЕН") + subtleStyle.Render(fmt.Sprintf(" (%v)\n", m.daemonErr)))
		b.WriteString(subtleStyle.Render("  [o] Запустить демон и включить перехват   [D] Только запустить демон\n"))
		return b.String()
	}

	s := m.snap
	stateStr := s.State
	switch s.State {
	case "ACTIVE":
		stateStr = okStyle.Render(stateStr)
	case "OFF":
		stateStr = subtleStyle.Render(stateStr)
	default:
		stateStr = boldStyle.Render(stateStr)
	}

	sinceStr := "-"
	if !s.Since.IsZero() {
		sinceStr = fmt.Sprintf("в состоянии %s, с %s",
			time.Since(s.Since).Truncate(time.Second),
			s.Since.Format("15:04:05"))
	}

	b.WriteString(fmt.Sprintf("  Статус:       %s (%s)\n", stateStr, sinceStr))
	if s.ProfileID != "" {
		b.WriteString(fmt.Sprintf("  Профиль:      %s\n", s.ProfileID))
	}

	if s.Tunnel != nil {
		tunHealth := errStyle.Render("offline")
		if s.Tunnel.Healthy {
			tunHealth = okStyle.Render("healthy")
		}
		b.WriteString(fmt.Sprintf("  Туннель:      %s (режим: %s, rx: %d B, tx: %d B, tcp_flows: %d)\n",
			tunHealth, s.Tunnel.Mode, s.Tunnel.RxBytes, s.Tunnel.TxBytes, s.Tunnel.TCPFlows))
	} else {
		b.WriteString("  Туннель:      (ветка не активна)\n")
	}

	b.WriteString(fmt.Sprintf("  Пакетов:      total %d | desync %d | redir %d | drop %d\n",
		s.Counters.PacketsTotal, s.Counters.PacketsDesync, s.Counters.PacketsRedir, s.Counters.PacketsDrop))

	if s.Counters.LastProbeNote != "" {
		b.WriteString(fmt.Sprintf("\n  Проба:        %s\n", subtleStyle.Render(s.Counters.LastProbeNote)))
	}

	b.WriteString(subtleStyle.Render(fmt.Sprintf("\n  (обновлено %s, опрос каждые 2с)\n", m.lastPoll.Format("15:04:05"))))
	return b.String()
}

func (m tuiModel) renderRules() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Правила маршрутизации (порядок = приоритет)") + "\n\n")

	b.WriteString(fmt.Sprintf("  %-3s  %-8s  %-35s  %-6s  %-8s\n", "№", "ТИП", "МАТЧЕР", "PROTO", "ACTION"))
	b.WriteString("  " + strings.Repeat("─", 68) + "\n")

	for i, r := range m.rules {
		mType := "DEFAULT"
		mVal := "*"
		if r.CIDR != "" {
			mType = "CIDR"
			mVal = r.CIDR
		} else if r.SNI != "" {
			mType = "SNI"
			mVal = r.SNI
		} else if r.Ports != "" {
			mType = "PORTS"
			mVal = r.Ports
		}

		proto := r.Proto
		if proto == "" {
			proto = "any"
		}

		actName := r.Action.String()
		actStr := fmt.Sprintf("%-8s", actName)
		switch r.Action {
		case config.ActionDirect:
			actStr = okStyle.Render(actStr)
		case config.ActionTunnel:
			actStr = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render(actStr)
		case config.ActionDesync:
			actStr = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render(actStr)
		case config.ActionBlock:
			actStr = errStyle.Render(actStr)
		}

		line := fmt.Sprintf("  %-3d  %-8s  %-35s  %-6s  %s", i+1, mType, truncateStr(mVal, 35), proto, actStr)
		if i == m.ruleSel {
			line = selRowStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	return b.String()
}

func (m tuiModel) renderDesync() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Параметры Desync") + "\n\n")

	hints := []string{
		"fake / split / multidisorder",
		"шаблон ClientHello (напр: build/desync/fake-chrome.bin)",
		"сырой TTL фейка (t*, 0 = автокалибровка)",
		"запас TTL к t* (по умолчанию 2)",
		"число повторов фейка (по умолчанию 6)",
		"смещение сплита в байтах (по умолчанию 2)",
	}

	for i := 0; i < len(m.desyncInputs); i++ {
		prefix := "  "
		if i == m.desyncFocus {
			prefix = boldStyle.Render("> ")
		}
		b.WriteString(prefix + m.desyncInputs[i].View() + "\n")
		b.WriteString("    " + subtleStyle.Render(hints[i]) + "\n\n")
	}

	return b.String()
}

func (m tuiModel) renderTunnels() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Конфигурация туннелей и эндпоинтов") + "\n\n")

	epNames := []string{"TCP (Primary)", "UDP (Hy2)", "Fallback (xHTTP)"}
	var epTabs []string
	for i, name := range epNames {
		if i == m.tunEndpoint {
			epTabs = append(epTabs, activeTabStyle.Render(name))
		} else {
			epTabs = append(epTabs, tabStyle.Render(name))
		}
	}
	b.WriteString("  " + lipgloss.JoinHorizontal(lipgloss.Top, epTabs...) + "\n\n")

	ep := m.getEndpoint(m.tunEndpoint)
	if ep == nil {
		b.WriteString("  (эндпоинт не настроен)\n")
	} else {
		fields := []struct {
			name string
			val  string
		}{
			{"Kind", ep.Kind},
			{"Host", ep.Host},
			{"Port", strconv.Itoa(int(ep.Port))},
			{"UUID", maskSecret(ep.UUID)},
			{"Password", maskSecret(ep.Password)},
			{"SNI", ep.SNI},
			{"ALPN", strings.Join(ep.ALPN, ",")},
			{"Fingerprint", ep.Fingerprint},
			{"Path", ep.Path},
		}

		for i, f := range fields {
			prefix := "  "
			if i == m.tunField {
				prefix = boldStyle.Render("> ")
			}
			b.WriteString(fmt.Sprintf("%s%-14s %s\n", prefix, f.name+":", f.val))
		}
	}

	b.WriteString("\n  " + strings.Repeat("─", 50) + "\n")
	xhttpStr := "[ ] выключен"
	if m.tunnels.xhttpFallbackInChain {
		xhttpStr = okStyle.Render("[x] включён в цепочку (xhttp_fallback_in_chain)")
	}
	b.WriteString("  " + xhttpStr + subtleStyle.Render(" (нажмите x для переключения)\n"))

	return b.String()
}

func (m tuiModel) renderModal() string {
	switch m.edit {
	case editConfirmDelete:
		box := fmt.Sprintf("Удалить правило #%d?\n\n[y] Да    [n] Отмена", m.ruleSel+1)
		return boxStyle.Render(box)

	case editTunnelSecret:
		box := fmt.Sprintf("Редактирование секрета\n\n%s\n\n[Enter] Принять   [Esc] Отмена", m.tunSecretIn.View())
		return boxStyle.Render(box)

	case editRuleWizard:
		var b strings.Builder
		title := "Новое правило"
		if !m.editNew {
			title = fmt.Sprintf("Редактирование правила #%d", m.ruleSel+1)
		}
		b.WriteString(headerStyle.Render(title) + "\n\n")

		types := []string{"CIDR", "SNI", "PORTS", "DEFAULT"}
		protos := []string{"any", "tcp", "udp"}
		actions := []string{"direct", "desync", "tunnel", "block"}

		b.WriteString("1. Тип матчера: ")
		for i, t := range types {
			if i == m.wizType {
				b.WriteString(boldStyle.Render("["+t+"]") + " ")
			} else {
				b.WriteString(subtleStyle.Render(t) + " ")
			}
		}
		b.WriteString("\n")

		if m.wizType != 3 {
			b.WriteString("2. Значение:    " + m.wizInput.View() + "\n")
			b.WriteString("3. Протокол:    ")
			for i, p := range protos {
				if i == m.wizProto {
					b.WriteString(boldStyle.Render("["+p+"]") + " ")
				} else {
					b.WriteString(subtleStyle.Render(p) + " ")
				}
			}
			b.WriteString("\n")
		}

		b.WriteString("4. Действие:    ")
		for i, a := range actions {
			if i == m.wizAct {
				b.WriteString(boldStyle.Render("["+a+"]") + " ")
			} else {
				b.WriteString(subtleStyle.Render(a) + " ")
			}
		}
		b.WriteString("\n")

		if m.wizErr != "" {
			b.WriteString("\n" + errStyle.Render("Ошибка: "+m.wizErr) + "\n")
		}

		b.WriteString(subtleStyle.Render("\n[←/→] выбор   [Enter] далее/сохранить   [Esc] отмена"))
		return boxStyle.Render(b.String())
	}
	return ""
}

func (m tuiModel) renderFooter() string {
	var b strings.Builder

	if m.statusMsg != "" {
		if m.statusIsErr {
			b.WriteString(errStyle.Render(" ● "+m.statusMsg) + "\n")
		} else {
			b.WriteString(okStyle.Render(" ● "+m.statusMsg) + "\n")
		}
	} else if m.dirty {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render(" ● Есть несохранённые изменения (s — сохранить)") + "\n")
	}

	var keys string
	switch m.activeTab {
	case tabStatus:
		keys = "[1-4/Tab] Вкладки  [o] Вкл/Запуск  [f] Выкл  [p] Probe  [r] Обновить  [D] Запустить демон  [q] Выход"
	case tabRules:
		keys = "[j/k/↑/↓] Выбор  [n] Новое  [e] Изменить  [d] Удалить  [J/K] Порядок  [s] Сохранить  [q] Выход"
	case tabDesync:
		keys = "[Tab/Enter] Поле  [↑/↓] Навигация  [s] Сохранить  [q] Выход"
	case tabTunnels:
		keys = "[h/l] Эндпоинт  [j/k] Поле  [e] Секрет  [x] XHTTP  [s] Сохранить  [q] Выход"
	}

	b.WriteString(subtleStyle.Render(keys))
	return b.String()
}

func maskSecret(s string) string {
	if s == "" {
		return subtleStyle.Render("(пусто)")
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", len(s)-4)
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
