package android

import (
	"context"
	"testing"

	"github.com/kshishtovsky/tuman/mux"
)

type fakeTMN struct {
	err   error
	opens int
}

func (f *fakeTMN) OpenUDP(context.Context, string, string) (*mux.Stream, error) {
	f.opens++
	return nil, f.err
}
func (f *fakeTMN) Close() error { return nil }

// A tmn-only profile has no sing-box relay, so UDP used to have no path at
// all: voice and QUIC fell through to direct. openUDP must hand out a tmn
// association instead — and still fail loudly when there is no path at all.
func TestOpenUDPFallsThroughToTMN(t *testing.T) {
	tmn := &fakeTMN{}
	e := &Engine{tmn: []tmnClient{tmn}, logFn: func(string) {}}
	up, err := e.openUDP(context.Background())
	if err != nil {
		t.Fatalf("tmn-путь не выбран: %v", err)
	}
	if _, ok := up.(tmnUDP); !ok {
		t.Fatalf("получили %T, ждали tmnUDP", up)
	}
	up.close()

	if _, err := (&Engine{logFn: func(string) {}}).openUDP(context.Background()); err == nil {
		t.Fatal("openUDP без релея и без кареток вернул успех")
	}
}
