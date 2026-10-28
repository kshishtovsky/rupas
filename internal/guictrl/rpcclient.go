// rpcclient.go — thin client for the rupasd control pipe (JSON-line protocol,
// internal/rpc/server.go). Kept here so guictrl has no dependency on CLI code.
package guictrl

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/kshishtovsky/rupas/internal/rpc"
)

// CallPipe sends one command and reads one response line.
func CallPipe(pipe string, cmd string, timeout time.Duration) (*rpc.Response, error) {
	conn, err := rpc.DialPipe(pipe, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req, _ := json.Marshal(rpc.Request{Cmd: cmd})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	rd := bufio.NewReader(conn)
	line, err := rd.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read: %w", err)
	}
	var resp rpc.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("bad response: %w", err)
	}
	return &resp, nil
}

// CallLogs reads the log tail stream (last N lifecycle events) to completion.
func CallLogs(pipe string, timeout time.Duration) ([]string, error) {
	conn, err := rpc.DialPipe(pipe, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req, _ := json.Marshal(rpc.Request{Cmd: "logs"})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	var out []string
	rd := bufio.NewReader(conn)
	for {
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 {
			var r struct {
				OK   bool              `json:"ok"`
				Data map[string]string `json:"data"`
			}
			if json.Unmarshal(line, &r) == nil && r.OK {
				out = append(out, r.Data["log"])
			}
		}
		if err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
	}
}

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
