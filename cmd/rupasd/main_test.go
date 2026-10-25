package main

import (
	"path/filepath"
	"testing"
)

// TestExampleConfigIsValid keeps configs/rupas.example.yaml loadable and
// honest: the empty tunnel section must validate (tunnel disabled, TUNNEL
// rules escalate) exactly like the shipped default profile.
func TestExampleConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "rupas.example.yaml")
	cfg, err := loadConfig(path, nil)
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	if cfg.Profile == "" {
		t.Fatal("example config lost its profile")
	}
	if cfg.Tunnel.Protocol != "" || cfg.Tunnel.Address != "" || cfg.Tunnel.Port != 0 {
		t.Fatalf("example endpoint must ship empty (placeholders live in the comments): %+v", cfg.Tunnel)
	}
	if len(cfg.Rules) < 5 {
		t.Fatalf("example rules thinned out: %d", len(cfg.Rules))
	}
}
