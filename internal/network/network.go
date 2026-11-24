// Package network follows the kind of network sinty-nm reports for the
// current connection, so the firewall profile matches where the device is.
package network

import (
	"context"

	"github.com/singularityos-lab/libsingularity/src/system/core/go/netkind"

	"github.com/singularityos-lab/sinty-firewalld/internal/state"
)

const Dir = netkind.Dir

func ProfileFor(k netkind.Kind) state.Profile {
	if k.Private() {
		return state.Home
	}
	return state.Public
}

func Read(dir string) (state.Profile, bool) {
	k, ok := netkind.Read(dir)
	if !ok {
		return "", false
	}
	return ProfileFor(k), true
}

func Follow(ctx context.Context, dir string, set func(state.Profile)) {
	last := state.Profile("")
	netkind.Watch(ctx, dir, func() {
		if p, ok := Read(dir); ok && p != last {
			last = p
			set(p)
		}
	})
}
