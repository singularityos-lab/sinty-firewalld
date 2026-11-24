package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/singularityos-lab/libsingularity/src/system/core/go/netkind"

	"github.com/singularityos-lab/sinty-firewalld/internal/state"
)

func TestOnlyKnownPrivateNetworksOpenTheHomeProfile(t *testing.T) {
	for kind, want := range map[string]state.Profile{
		"home\n": state.Home, "work": state.Home, "public": state.Public,
		"none": state.Public, "": state.Public, "garbage": state.Public,
	} {
		if got := ProfileFor(netkind.Parse(kind)); got != want {
			t.Errorf("%q: %s, want %s", kind, got, want)
		}
	}
}

func TestTheProfileFollowsTheNetwork(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sinty-nm")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan state.Profile, 8)
	go Follow(ctx, dir, func(p state.Profile) { got <- p })
	write := func(kind string) {
		tmp := filepath.Join(dir, ".network-kind")
		os.WriteFile(tmp, []byte(kind+"\n"), 0o644)
		os.Rename(tmp, filepath.Join(dir, "network-kind"))
	}
	expect := func(want state.Profile) {
		t.Helper()
		select {
		case p := <-got:
			if p != want {
				t.Fatalf("profile %s, want %s", p, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no change to %s", want)
		}
	}
	os.MkdirAll(dir, 0o755)
	write("home")
	expect(state.Home)
	write("public")
	expect(state.Public)
	write("public")
	write("work")
	expect(state.Home)
	os.RemoveAll(dir)
	os.MkdirAll(dir, 0o755)
	write("none")
	expect(state.Public)
}
