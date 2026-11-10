// Package state holds the firewall settings sinty-firewalld applies: whether
// the firewall is on, which network profile is active and which apps may
// receive connections on which ports.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func (s State) Allow(r Rule) (State, error) {
	if err := ValidID(r.ID); err != nil {
		return s, err
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
// network only the apps that asked to be reachable there too.
func (s State) Active() []Rule {
	var out []Rule
	for _, r := range s.Rules {
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
