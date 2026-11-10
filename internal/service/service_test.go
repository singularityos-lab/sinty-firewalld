package service

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-firewalld/internal/state"
)

type recorder struct {
	applied []state.State
	fail    bool
}

func (r *recorder) Apply(s state.State) error {
	if r.fail {
		r.fail = false
		return errors.New("kernel refused")
	}
	r.applied = append(r.applied, s)
	return nil
}

func newService(t *testing.T) (*Service, *recorder, string) {
	path := filepath.Join(t.TempDir(), "state.json")
	rec := &recorder{}
	s, err := New(path, rec)
	if err != nil {
		t.Fatal(err)
	}
	return s, rec, path
}

func TestStartAppliesSavedState(t *testing.T) {
	s, rec, path := newService(t)
	if err := s.Allow(state.Rule{ID: "ssh", Ports: "22/tcp", Label: "Remote Login"}); err != nil {
		t.Fatal(err)
	}
	again, _ := New(path, rec)
	rec.applied = nil
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	if len(rec.applied) != 1 || len(rec.applied[0].Rules) != 1 {
		t.Fatalf("start applied %+v", rec.applied)
	}
}

func TestRefusedApplyKeepsOldState(t *testing.T) {
	s, rec, path := newService(t)
	s.Allow(state.Rule{ID: "ssh", Ports: "22/tcp", Label: "Remote Login"})
	rec.fail = true
	if err := s.Allow(state.Rule{ID: "web", Ports: "8000/tcp", Label: "Preview"}); err == nil {
		t.Fatal("a refused ruleset was reported as applied")
	}
	if got := s.State(); len(got.Rules) != 1 {
		t.Fatalf("state after refusal %+v", got.Rules)
	}
	if last := rec.applied[len(rec.applied)-1]; len(last.Rules) != 1 {
		t.Fatalf("previous ruleset not restored: %+v", last)
	}
	saved, _ := state.Load(path)
	if len(saved.Rules) != 1 {
		t.Fatalf("saved %+v", saved.Rules)
	}
}

func TestBusErrors(t *testing.T) {
	s, _, _ := newService(t)
	o := &object{s}
	if err := o.Allow("", "Bad Id", false, "22/tcp", "X"); err == nil || err.Name != Iface+".Error.Invalid" {
		t.Fatalf("got %v", err)
	}
	if err := o.SetProfile("", "cafe"); err == nil || err.Name != Iface+".Error.Invalid" {
		t.Fatalf("got %v", err)
	}
	s.authorize = func(dbus.Sender) (uint32, bool) { return 999, false }
	if err := o.SetEnabled(":1.5", false); err == nil || err.Name != "org.freedesktop.DBus.Error.AccessDenied" {
		t.Fatalf("got %v", err)
	}
	enabled, profile, rules, _ := o.Status()
	if !enabled || profile != "home" || len(rules) != 0 {
		t.Fatalf("status %v %v %v", enabled, profile, rules)
	}
}

func TestProfileSwitchAppliesActiveRules(t *testing.T) {
	s, rec, _ := newService(t)
	s.Allow(state.Rule{ID: "ssh", Ports: "22/tcp", Label: "Remote Login"})
	s.Allow(state.Rule{ID: "web", Ports: "8000/tcp", Label: "Preview", PublicToo: true})
	if err := s.SetProfile("public"); err != nil {
		t.Fatal(err)
	}
	last := rec.applied[len(rec.applied)-1]
	if last.Profile != state.Public || len(last.Active()) != 1 {
		t.Fatalf("public ruleset %+v", last)
	}
}
