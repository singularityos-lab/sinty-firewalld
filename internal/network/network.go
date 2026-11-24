// Package network follows the kind of network sinty-nm reports for the
// current connection, so the firewall profile matches where the device is.
package network

import (
	"context"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

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
	report := func() {
		if p, ok := Read(dir); ok && p != last {
			last = p
			set(p)
		}
	}
	for ctx.Err() == nil {
		fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
		if err != nil {
			return
		}
		if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF); err != nil {
			unix.Close(fd)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		report()
		watch(ctx, fd, report)
		unix.Close(fd)
	}
}

func watch(ctx context.Context, fd int, report func()) {
	buf := make([]byte, 4096)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		n, err := unix.Poll(fds, 1000)
		if err != nil && err != unix.EINTR {
			return
		}
		if n <= 0 {
			continue
		}
		got, err := unix.Read(fd, buf)
		if err != nil || got <= 0 {
			continue
		}
		gone := false
		for off := 0; off+unix.SizeofInotifyEvent <= got; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			if ev.Mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 {
				gone = true
			}
			off += unix.SizeofInotifyEvent + int(ev.Len)
		}
		report()
		if gone {
			return
		}
	}
}
