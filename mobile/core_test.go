package core

import "testing"

func TestSetSettingsValidateAndClear(t *testing.T) {
	mu.Lock()
	saved := settings
	mu.Unlock()
	defer func() {
		mu.Lock()
		settings = saved
		mu.Unlock()
	}()

	if err := SetSettings(`{"uuid":"u","server":"s","port":443,"sni":"x","public_key":"p","short_id":"01","fallback":true}`); err != nil {
		t.Fatalf("valid settings: %v", err)
	}
	if err := SetSettings(`{"nope":1}`); err == nil {
		t.Fatal("invalid settings must be rejected")
	}
	if err := SetSettings(""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	mu.Lock()
	if settings != nil {
		t.Fatal("settings must be cleared")
	}
	mu.Unlock()
}
