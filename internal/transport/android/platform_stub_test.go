package android

import (
	"testing"
	"github.com/sagernet/sing-box/adapter"
)

func TestNopPlatform_SendNotification(t *testing.T) {
	p := nopPlatform{}

	// nil — не паникует, возвращает nil.
	if err := p.SendNotification(nil); err != nil {
		t.Fatalf("SendNotification(nil) = %v", err)
	}

	n := &adapter.Notification{Title: "test"}
	if err := p.SendNotification(n); err != nil {
		t.Fatalf("SendNotification(&notif) = %v", err)
	}
}

func TestNopPlatform_SendNotification_doesNotReturnErrNotSupported(t *testing.T) {
	// Раньше SendNotification возвращал errNotSupported — Go-сторона
	// молча падала. Теперь — safe stub, nil.
	p := nopPlatform{}
	if err := p.SendNotification(&adapter.Notification{}); err == errNotSupported {
		t.Error("SendNotification вернул errNotSupported; ожидает nil (safe stub)")
	}
}
