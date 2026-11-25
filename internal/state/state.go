// Package state holds the firewall settings sinty-firewalld applies: whether
// the firewall is on, which network profile is active and which apps may
// receive connections on which ports.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const MaxRules = 64

type Profile string

const (
	Home   Profile = "home"
	Public Profile = "public"
)

type Rule struct {
	ID        string `json:"id"`
	PublicToo bool   `json:"public_too"`
	Ports     string `json:"ports"`
	Label     string `json:"label"`
}

type State struct {
	Enabled bool    `json:"enabled"`
	Profile Profile `json:"profile"`
	Rules   []Rule  `json:"rules"`
	System  []Rule  `json:"-"`
}

func Default() State {
	return State{Profile: Home}
}

var (
	ErrID      = errors.New("an app id is 1 to 32 characters of a-z, 0-9 and -")
	ErrLabel   = errors.New("a label is 1 to 64 printable characters without quotes or backslashes")
	ErrPorts   = errors.New("ports are a comma separated list of PORT/tcp, PORT/udp or FIRST-LAST/tcp")
	ErrProfile = errors.New("the profile is home or public")
	ErrFull    = fmt.Errorf("at most %d apps can receive connections", MaxRules)
	ErrSystem  = errors.New("this rule belongs to a system service")
)

func ValidID(id string) error {
	if len(id) == 0 || len(id) > 32 {
		return ErrID
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return ErrID
		}
	}
	return nil
}

func ValidLabel(label string) error {
	if len(label) == 0 || len(label) > 64 {
		return ErrLabel
	}
	for _, c := range label {
		if c < 0x20 || c == 0x7f || c == '"' || c == '\\' {
			return ErrLabel
		}
	}
	return nil
}

func ValidPorts(spec string) error {
	items := strings.Split(spec, ",")
	if spec == "" || len(items) > 16 {
		return ErrPorts
	}
	for _, item := range items {
		num, proto, ok := strings.Cut(item, "/")
		if !ok || (proto != "tcp" && proto != "udp") {
			return ErrPorts
		}
		first, last, isRange := strings.Cut(num, "-")
		if !isRange {
			last = first
		}
		a, err1 := strconv.Atoi(first)
		b, err2 := strconv.Atoi(last)
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || b < a {
			return ErrPorts
		}
	}
	return nil
}

func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case Home, Public:
		return Profile(s), nil
	}
	return "", ErrProfile
}

func (s State) system(id string) (Rule, bool) {
	for _, r := range s.System {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

func (s State) Allow(r Rule) (State, error) {
	if err := ValidID(r.ID); err != nil {
		return s, err
	}
	if sys, ok := s.system(r.ID); ok {
		if sys.Ports == r.Ports && sys.PublicToo == r.PublicToo {
			return s, nil
		}
		return s, ErrSystem
	}
	if err := ValidLabel(r.Label); err != nil {
		return s, err
	}
	if err := ValidPorts(r.Ports); err != nil {
		return s, err
	}
	out := s.clone()
	for i := range out.Rules {
		if out.Rules[i].ID == r.ID {
			out.Rules[i] = r
			return out, nil
		}
	}
	if len(out.Rules) >= MaxRules {
		return s, ErrFull
	}
	out.Rules = append(out.Rules, r)
	return out, nil
}

func (s State) Revoke(id string) (State, error) {
	if err := ValidID(id); err != nil {
		return s, err
	}
	if _, ok := s.system(id); ok {
		return s, ErrSystem
	}
	out := s.clone()
	out.Rules = out.Rules[:0]
	for _, r := range s.Rules {
		if r.ID != id {
			out.Rules = append(out.Rules, r)
		}
	}
	return out, nil
}

func (s State) clone() State {
	out := s
	out.Rules = append([]Rule(nil), s.Rules...)
	return out
}

// Active lists the rules that apply under the current profile: on a public
// network only the services and apps that asked to be reachable there too.
func (s State) Active() []Rule {
	var out []Rule
	for _, r := range append(append([]Rule(nil), s.System...), s.Rules...) {
		if s.Profile == Public && !r.PublicToo {
			continue
		}
		out = append(out, r)
	}
	return out
}

func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Default(), err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	if _, err := ParseProfile(string(s.Profile)); err != nil {
		s.Profile = Home
	}
	valid := s.Rules[:0]
	for _, r := range s.Rules {
		if ValidID(r.ID) == nil && ValidLabel(r.Label) == nil && ValidPorts(r.Ports) == nil && len(valid) < MaxRules {
			valid = append(valid, r)
		}
	}
	s.Rules = valid
	return s, nil
}

func (s State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// LoadServices reads the ports system services declare, one NAME.json file per
// service holding {"label", "ports", "public_too"}. A file in a later directory
// replaces the one with the same name in an earlier directory, so /etc can
// override what a package ships.
func LoadServices(dirs ...string) []Rule {
	byID := map[string]Rule{}
	var order []string
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(files)
		for _, f := range files {
			id := strings.TrimSuffix(filepath.Base(f), ".json")
			data, err := os.ReadFile(f)
			if err != nil {
				log.Printf("%s: %v", f, err)
				continue
			}
			var r Rule
			if err := json.Unmarshal(data, &r); err != nil {
				log.Printf("%s: %v", f, err)
				continue
			}
			r.ID = id
			if err := errors.Join(ValidID(r.ID), ValidLabel(r.Label), ValidPorts(r.Ports)); err != nil {
				log.Printf("%s: %v", f, err)
				continue
			}
			if _, seen := byID[id]; !seen {
				order = append(order, id)
			}
			byID[id] = r
		}
	}
	out := make([]Rule, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}
