// Package rpc exposes the Rupas control plane over a Windows named pipe
// (SYSTEM_DESIGN §9): JSON-line request/response plus a streaming mode for
// the last lifecycle events. The pipe DACL grants access to SYSTEM and the
// interactive user only.
package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"runtime/pprof"
	"strings"
	"sync"

	"github.com/rupas/rupas/internal/core"
)

// DefaultPipe is the canonical control pipe path (§9).
const DefaultPipe = `\\.\pipe\rupasctl`

// maxLineBytes caps one JSON-line request; anything larger is rejected to
// keep a rogue client from ballooning daemon memory (§10: pipe hardening).
const maxLineBytes = 64 * 1024

// logTailLines is how many lifecycle events the "logs" command streams
// (§11: "последние 100 событий").
const logTailLines = 100

// Request is one JSON-line command: {"cmd":"status|on|off|probe|reload|logs"}.
type Request struct {
	Cmd string `json:"cmd"`
}

// Response is the universal reply: {"ok":bool,"data":...} plus "error" on
// failure. Streaming replies ("logs") emit one Response per line.
type Response struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// Deps are the callbacks wired by the daemon; the supervisor implements
// the semantics, rpc only frames them.
type Deps struct {
	Status func() core.Snapshot
	On     func() error
	Off    func() error
	Probe  func() error
	Reload func() error
	// Logs returns the last n lifecycle events, oldest first.
	Logs   func(n int) []string
	Logger *log.Logger // optional
}

// listener is the platform seam: the Windows named-pipe implementation
// lives in pipe_windows.go.
type listener interface {
	Accept() (io.ReadWriteCloser, error)
	Close() error
}

// Server serves the JSON-line protocol on a named pipe.
type Server struct {
	pipe      string
	deps      Deps
	mu        sync.Mutex
	ln        listener
	done      chan struct{}
	closeOnce sync.Once
}

// New normalizes the pipe name and returns a Server. Pass "" for the
// default pipe.
func New(pipe string, deps Deps) *Server {
	if pipe == "" {
		pipe = DefaultPipe
	}
	if !strings.HasPrefix(pipe, `\\.\pipe\`) {
		pipe = `\\.\pipe\` + pipe
	}
	return &Server{pipe: pipe, deps: deps, done: make(chan struct{})}
}

func (s *Server) logf(format string, v ...any) {
	if s.deps.Logger != nil {
		s.deps.Logger.Printf("rpc: "+format, v...)
	}
}

// ListenAndServe blocks accepting connections until ctx is cancelled or
// Close is called.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := newPipeListener(s.pipe)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.pipe, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.done:
		}
	}()

	s.logf("listening on %s", s.pipe)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				return fmt.Errorf("accept %s: %w", s.pipe, err)
			}
		}
		go s.handleConn(conn)
	}
}

// Close stops the listener. In-flight connections finish their current
// line and end when the client goes away.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		ln := s.ln
		s.mu.Unlock()
		if ln != nil {
			err = ln.Close()
		}
	})
	return err
}

func (s *Server) handleConn(conn io.ReadWriteCloser) {
	defer conn.Close()
	rd := bufio.NewReaderSize(conn, 4096)
	wr := bufio.NewWriter(conn)
	for {
		line, err := rd.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if s.handleLine(bytes.TrimSpace(line), wr) {
				return // stream finished or write failed: end of session
			}
		}
		if err != nil {
			return // EOF or broken pipe
		}
	}
}

// handleLine serves one request; it returns true when the connection must
// be closed afterwards (end of a "logs" stream or a dead writer).
func (s *Server) handleLine(line []byte, wr *bufio.Writer) bool {
	if len(line) > maxLineBytes {
		return !s.write(wr, Response{OK: false, Error: "request too large"})
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return !s.write(wr, Response{OK: false, Error: "bad request: " + err.Error()})
	}
	if req.Cmd == "logs" {
		return s.streamLogs(wr)
	}
	return !s.write(wr, s.dispatch(req.Cmd))
}

func (s *Server) streamLogs(wr *bufio.Writer) bool {
	if s.deps.Logs == nil {
		return !s.write(wr, Response{OK: false, Error: "logs not wired"})
	}
	for _, l := range s.deps.Logs(logTailLines) {
		if !s.write(wr, Response{OK: true, Data: map[string]string{"log": l}}) {
			return true
		}
	}
	return true // stream complete: half-close the session
}

func (s *Server) dispatch(cmd string) Response {
	switch cmd {
	case "status":
		if s.deps.Status == nil {
			return Response{OK: false, Error: "status not wired"}
		}
		return Response{OK: true, Data: s.deps.Status()}
	case "on":
		return callDep("on", s.deps.On)
	case "off":
		return callDep("off", s.deps.Off)
	case "probe":
		return callDep("probe", s.deps.Probe)
	case "reload":
		return callDep("reload", s.deps.Reload)
	default:
		if cmd == "debug" {
			var buf bytes.Buffer
			pprof.Lookup("goroutine").WriteTo(&buf, 2)
			return Response{OK: true, Data: map[string]string{"goroutines": buf.String()}}
		}
		return Response{OK: false, Error: fmt.Sprintf("unknown cmd %q (want status|on|off|probe|reload|logs|debug)", cmd)}
	}
}

func callDep(name string, fn func() error) Response {
	if fn == nil {
		return Response{OK: false, Error: name + " not wired"}
	}
	if err := fn(); err != nil {
		return Response{OK: false, Error: name + ": " + err.Error()}
	}
	return Response{OK: true}
}

func (s *Server) write(wr *bufio.Writer, r Response) bool {
	b, err := json.Marshal(r)
	if err != nil {
		return false
	}
	if _, err := wr.Write(append(b, '\n')); err != nil {
		return false
	}
	return wr.Flush() == nil
}
