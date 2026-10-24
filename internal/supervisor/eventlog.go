package supervisor

import (
	"sync"
	"time"
)

// EventLog is a fixed-size ring of the last lifecycle events, exposed to
// the RPC "logs" command (SYSTEM_DESIGN §9: streaming events for logs) and
// the future diag bundle (§11: "последние 100 событий").
type EventLog struct {
	mu    sync.Mutex
	lines []string
	max   int
}

// NewEventLog returns a ring keeping the last max lines (max <= 0 → 100).
func NewEventLog(max int) *EventLog {
	if max <= 0 {
		max = 100
	}
	return &EventLog{max: max}
}

// Append adds one timestamped line, evicting the oldest past max.
func (l *EventLog) Append(text string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, time.Now().Format(time.RFC3339)+" "+text)
	if over := len(l.lines) - l.max; over > 0 {
		l.lines = l.lines[over:]
	}
}

// Last returns up to n most recent lines, oldest first. n <= 0 → all.
func (l *EventLog) Last(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.lines) {
		n = len(l.lines)
	}
	out := make([]string, n)
	copy(out, l.lines[len(l.lines)-n:])
	return out
}

// Len returns the number of buffered lines.
func (l *EventLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}
