// Command rupasctl is the CLI client of the Rupas daemon: it speaks the
// JSON-line protocol over the control named pipe (§9) and renders the
// supervisor snapshot as a readable table.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/rpc"
)

const usage = `usage: rupasctl [-pipe \\.\pipe\rupasctl] <command>

commands:
  status   show supervisor state, flows and counters
  on       turn interception on
  off      turn interception off and stop the pipeline
  probe    force immediate re-classification
  reload   reload the daemon config
  logs     stream the last lifecycle events
`

func main() {
	pipe := flag.String("pipe", rpc.DefaultPipe, "control named pipe path")
	timeout := flag.Duration("timeout", 3*time.Second, "connect timeout")
	flag.Parse()

	cmd := ""
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	switch cmd {
	case "status", "on", "off", "probe", "reload", "logs":
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	if err := run(*pipe, *timeout, cmd); err != nil {
		fmt.Fprintf(os.Stderr, "rupasctl: %v\n", err)
		os.Exit(1)
	}
}

func run(pipePath string, timeout time.Duration, cmd string) error {
	conn, err := rpc.DialPipe(pipePath, timeout)
	if err != nil {
		return fmt.Errorf("cannot reach daemon at %s (is rupasd running?): %w", pipePath, err)
	}
	defer conn.Close()

	req, _ := json.Marshal(rpc.Request{Cmd: cmd})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	rd := bufio.NewReader(conn)
	switch cmd {
	case "logs":
		for {
			line, err := rd.ReadBytes('\n')
			if len(line) > 0 {
				var r struct {
					OK    bool              `json:"ok"`
					Data  map[string]string `json:"data"`
					Error string            `json:"error"`
				}
				if json.Unmarshal(line, &r) == nil && r.OK {
					fmt.Println(r.Data["log"])
				}
			}
			if err != nil {
				if err != io.EOF {
					return err
				}
				return nil // stream finished
			}
		}
	default:
		line, err := rd.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		var r struct {
			OK    bool          `json:"ok"`
			Data  core.Snapshot `json:"data"`
			Error string        `json:"error"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("bad response %q: %w", line, err)
		}
		if !r.OK {
			return fmt.Errorf("%s", r.Error)
		}
		if cmd == "status" {
			renderSnapshot(os.Stdout, r.Data)
			return nil
		}
		fmt.Printf("%s: ok\n", cmd)
		return nil
	}
}

// renderSnapshot prints the supervisor status as a compact table.
func renderSnapshot(w io.Writer, s core.Snapshot) {
	fmt.Fprintln(w, "Rupas status")
	fmt.Fprintf(w, "  state:      %s\n", s.State)
	if !s.Since.IsZero() {
		fmt.Fprintf(w, "  in state:   %s (since %s)\n", humanDur(time.Since(s.Since)), s.Since.Local().Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintf(w, "  profile:    %s\n", orDash(s.ProfileID))
	renderTunnel(w, s)

	if len(s.Flows) > 0 {
		fmt.Fprintln(w, "  flows:")
		keys := make([]string, 0, len(s.Flows))
		for k := range s.Flows {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "    %-12s %10d\n", k, s.Flows[k])
		}
	}

	c := s.Counters
	fmt.Fprintln(w, "  counters:")
	fmt.Fprintf(w, "    packets (total/pass/desync/redir/drop)  %d / %d / %d / %d / %d\n",
		c.PacketsTotal, c.PacketsPass, c.PacketsDesync, c.PacketsRedir, c.PacketsDrop)
	fmt.Fprintf(w, "    handshake (ok/fail)                     %d / %d\n", c.HandshakeOK, c.HandshakeFail)
	fmt.Fprintf(w, "    tunnel rx/tx                            %s / %s\n", humanBytes(c.TunnelRx), humanBytes(c.TunnelTx))
	if !c.LastProbeAt.IsZero() {
		fmt.Fprintf(w, "    last probe: %s — %s\n", c.LastProbeAt.Local().Format("2006-01-02 15:04:05"), orDash(c.LastProbeNote))
	} else {
		fmt.Fprintf(w, "    last probe: %s\n", "—")
	}
}

// renderTunnel prints the tunnel-branch section (§3.3/§6): mode, health,
// relayed bytes, flows and honest drop counters.
func renderTunnel(w io.Writer, s core.Snapshot) {
	t := s.Tunnel
	if t == nil {
		fmt.Fprintf(w, "  tunnel:     %s (no tunnel branch assembled)\n", healthy(s.TunnelHealthy))
		return
	}
	state := healthy(t.Healthy)
	if t.Held {
		state = "held (new flows dropped)"
	}
	switch t.Mode {
	case "tunnel":
		fmt.Fprintf(w, "  tunnel:     %s (mode: tunnel — NAT → tproxy → vless+reality)\n", state)
	case "escalated":
		fmt.Fprintf(w, "  tunnel:     %s (mode: escalated — no endpoint, %d TUNNEL rule(s) → sni:desync / cidr,port:direct)\n",
			state, t.EscalatedRules)
	case "off":
		fmt.Fprintf(w, "  tunnel:     %s (mode: off — TUNNEL rules demoted to direct)\n", state)
	default:
		fmt.Fprintf(w, "  tunnel:     %s (mode: %s)\n", state, orDash(t.Mode))
	}
	if t.Mode == "tunnel" {
		fmt.Fprintf(w, "    bytes rx/tx      %s / %s\n", humanBytes(t.RxBytes), humanBytes(t.TxBytes))
		fmt.Fprintf(w, "    flows tcp        %d active / %d total\n", t.TCPFlows, t.TCPConns)
		fmt.Fprintf(w, "    flows udp        %d sessions / %d datagrams\n", t.UDPSessions, t.UDPDgrams)
		fmt.Fprintf(w, "    dropped          %d\n", t.Dropped)
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func healthy(ok bool) string {
	if ok {
		return "healthy"
	}
	return "down"
}

func humanDur(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
