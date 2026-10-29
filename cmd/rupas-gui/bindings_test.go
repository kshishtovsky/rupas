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
