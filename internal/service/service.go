// Package service exports dev.sinty.Firewall1 on the system bus.
package service

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"

	"github.com/singularityos-lab/sinty-firewalld/internal/state"
)

const (
	Name  = "dev.sinty.Firewall1"
	Path  = dbus.ObjectPath("/dev/sinty/Firewall1")
	Iface = "dev.sinty.Firewall1"
)

// Applier puts a state into the kernel. The real one goes through
// libsinty-system-core; tests use a recording fake.
type Applier interface {
	Apply(s state.State) error
}

type Authorizer func(sender dbus.Sender) (uint32, bool)

type Service struct {
	mu        sync.Mutex
	cur       state.State
	path      string
	apply     Applier
	authorize Authorizer
	emit      func(state.State)
}

func New(path string, apply Applier) (*Service, error) {
	s, err := state.Load(path)
	if err != nil {
		log.Printf("state: %v, starting from defaults", err)
	}
	return &Service{cur: s, path: path, apply: apply, emit: func(state.State) {}}, nil
}

// Start applies the saved state so the ruleset is in place before anyone asks.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apply.Apply(s.cur)
}

func (s *Service) Export(conn *dbus.Conn) error {
	s.authorize = func(sender dbus.Sender) (uint32, bool) {
		var uid uint32
		if err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid); err != nil {
			return 0, false
		}
		return uid, uid == 0 || uid >= 1000
	}
	s.emit = func(st state.State) {
		enabled, profile, rules := wire(st)
		conn.Emit(Path, Iface+".Changed", enabled, profile, rules)
	}
	obj := &object{s}
	if err := conn.Export(obj, Path, Iface); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(Path),
		Interfaces: []introspect.Interface{introspect.IntrospectData, {
			Name:    Iface,
			Methods: introspect.Methods(obj),
			Signals: []introspect.Signal{{Name: "Changed", Args: []introspect.Arg{
				{Name: "enabled", Type: "b"}, {Name: "profile", Type: "s"}, {Name: "rules", Type: "a(sbss)"},
			}}},
		}},
	}
	return conn.Export(introspect.NewIntrospectable(node), Path, "org.freedesktop.DBus.Introspectable")
}

type Rule struct {
	ID        string
	PublicToo bool
	Ports     string
	Label     string
}

func wire(st state.State) (bool, string, []Rule) {
	rules := make([]Rule, 0, len(st.Rules))
	for _, r := range st.Rules {
		rules = append(rules, Rule{r.ID, r.PublicToo, r.Ports, r.Label})
	}
	return st.Enabled, string(st.Profile), rules
}

// change applies next to the kernel first and saves it only when that worked,
// so the file on disk never claims a ruleset the kernel refused.
func (s *Service) change(next state.State) error {
	if err := s.apply.Apply(next); err != nil {
		if aerr := s.apply.Apply(s.cur); aerr != nil {
			log.Printf("restoring the previous ruleset: %v", aerr)
		}
		return err
	}
	if err := next.Save(s.path); err != nil {
		log.Printf("saving %s: %v", s.path, err)
	}
	s.cur = next
	s.emit(next)
	return nil
}

func (s *Service) State() state.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *Service) SetEnabled(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cur
	next.Enabled = on
	return s.change(next)
}

func (s *Service) SetProfile(name string) error {
	p, err := state.ParseProfile(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cur
	next.Profile = p
	return s.change(next)
}

func (s *Service) Allow(r state.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.cur.Allow(r)
	if err != nil {
		return err
	}
	return s.change(next)
}

func (s *Service) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.cur.Revoke(id)
	if err != nil {
		return err
	}
	return s.change(next)
}

type object struct{ s *Service }

func (o *object) gate(sender dbus.Sender, action string) *dbus.Error {
	if o.s.authorize == nil {
		return nil
	}
	if uid, ok := o.s.authorize(sender); !ok {
		return dbus.NewError("org.freedesktop.DBus.Error.AccessDenied",
			[]interface{}{fmt.Sprintf("not authorized to %s (caller uid %d)", action, uid)})
	}
	return nil
}

func failure(err error) *dbus.Error {
	if err == nil {
		return nil
	}
	for _, bad := range []error{state.ErrID, state.ErrLabel, state.ErrPorts, state.ErrProfile, state.ErrFull} {
		if errors.Is(err, bad) {
			return dbus.NewError(Iface+".Error.Invalid", []interface{}{err.Error()})
		}
	}
	return dbus.NewError(Iface+".Error.Failed", []interface{}{err.Error()})
}

func (o *object) Status() (bool, string, []Rule, *dbus.Error) {
	enabled, profile, rules := wire(o.s.State())
	return enabled, profile, rules, nil
}

func (o *object) SetEnabled(sender dbus.Sender, on bool) *dbus.Error {
	if err := o.gate(sender, "change the firewall"); err != nil {
		return err
	}
	return failure(o.s.SetEnabled(on))
}

func (o *object) SetProfile(sender dbus.Sender, profile string) *dbus.Error {
	if err := o.gate(sender, "change the network profile"); err != nil {
		return err
	}
	return failure(o.s.SetProfile(profile))
}

func (o *object) Allow(sender dbus.Sender, id string, publicToo bool, ports, label string) *dbus.Error {
	if err := o.gate(sender, "open ports"); err != nil {
		return err
	}
	return failure(o.s.Allow(state.Rule{ID: id, PublicToo: publicToo, Ports: ports, Label: label}))
}

func (o *object) Revoke(sender dbus.Sender, id string) *dbus.Error {
	if err := o.gate(sender, "close ports"); err != nil {
		return err
	}
	return failure(o.s.Revoke(id))
}
