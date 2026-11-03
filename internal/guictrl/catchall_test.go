package guictrl

import (
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

func TestEnsureCatchAll(t *testing.T) {
	// No catch-all → a tunnel catch-all is appended (fail closed).
	got := ensureCatchAll([]config.Rule{{SNI: "a.ru", Action: config.ActionDirect}})
	if len(got) != 2 || got[1].Action != config.ActionTunnel || got[1].SNI != "" {
		t.Fatalf("missing catch-all not appended: %+v", got)
	}
	// A deliberate default: direct must survive untouched.
	in := []config.Rule{{SNI: "a.ru", Action: config.ActionDirect}, {Action: config.ActionDirect}}
	if got := ensureCatchAll(in); len(got) != 2 || got[1].Action != config.ActionDirect {
		t.Fatalf("explicit default was rewritten: %+v", got)
	}
}
