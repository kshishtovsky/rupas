package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kshishtovsky/rupas/internal/guictrl"
)

// TestFrontendBoundFQN guards the one string the frontend hardcodes: Wails
// resolves every call by package path (bindings.go: fqn = PkgPath.Type.Method),
// so a module rename silently breaks every GUI call with
// "unknown bound method name" while the build stays green.
func TestFrontendBoundFQN(t *testing.T) {
	tp := reflect.TypeOf(&guictrl.Controller{}).Elem()
	want := tp.PkgPath() + "." + tp.Name()
	js, err := assets.ReadFile("frontend/dist/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	if !strings.Contains(string(js), `"`+want+`"`) {
		t.Fatalf("app.js FQN does not match the bound service %q", want)
	}
}

// TestTrayLabel pins the snapshot → tray caption mapping: the label is the
// only status a user sees while the window is in the tray.
func TestTrayLabel(t *testing.T) {
	cases := []struct {
		name string
		snap guictrl.Snapshot
		want string
	}{
		{"daemon down", guictrl.Snapshot{Online: false, State: "ACTIVE"}, "Rupas — демон не запущен"},
		{"active", guictrl.Snapshot{Online: true, State: "ACTIVE"}, "Rupas — работает"},
		{"tunnel only", guictrl.Snapshot{Online: true, State: "ACTIVE_TUNNEL_ONLY"}, "Rupas — работает (туннель)"},
		{"probing", guictrl.Snapshot{Online: true, State: "PROBING"}, "Rupas — пробинг…"},
		{"degraded", guictrl.Snapshot{Online: true, State: "DEGRADED"}, "Rupas — сбой"},
		{"other", guictrl.Snapshot{Online: true, State: "OFF"}, "Rupas — выключено"},
	}
	for _, c := range cases {
		if got := trayLabel(c.snap); got != c.want {
			t.Errorf("%s: trayLabel = %q, want %q", c.name, got, c.want)
		}
	}
}
