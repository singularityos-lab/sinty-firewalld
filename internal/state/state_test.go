package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidation(t *testing.T) {
	for _, id := range []string{"", "Upper", "with space", "a/b", "0123456789012345678901234567890123"} {
		if ValidID(id) == nil {
			t.Errorf("id %q accepted", id)
		}
	}
	for _, p := range []string{"", "80", "80/sctp", "0/tcp", "70000/tcp", "90-80/tcp", "a/tcp", "22/tcp,"} {
		if ValidPorts(p) == nil {
			t.Errorf("ports %q accepted", p)
		}
	}
	for _, p := range []string{"22/tcp", "8000-8010/tcp,5353/udp", "65535/udp"} {
		if err := ValidPorts(p); err != nil {
			t.Errorf("ports %q refused: %v", p, err)
		}
	}
	for _, l := range []string{"", "a\"b", "a\\b", "tab\there"} {
		if ValidLabel(l) == nil {
			t.Errorf("label %q accepted", l)
		}
	}
}

func TestAllowReplaceRevoke(t *testing.T) {
	s := Default()
	s, err := s.Allow(Rule{ID: "ssh", Ports: "22/tcp", Label: "Remote Login"})
	if err != nil {
		t.Fatal(err)
	}
	s, _ = s.Allow(Rule{ID: "web", Ports: "8000/tcp", Label: "Preview", PublicToo: true})
	s, _ = s.Allow(Rule{ID: "ssh", Ports: "2222/tcp", Label: "Remote Login"})
	if len(s.Rules) != 2 || s.Rules[0].Ports != "2222/tcp" {
		t.Fatalf("replace failed: %+v", s.Rules)
	}
	s.Profile = Public
	if a := s.Active(); len(a) != 1 || a[0].ID != "web" {
		t.Fatalf("public profile kept %+v", a)
	}
	s, _ = s.Revoke("ssh")
	if len(s.Rules) != 1 {
		t.Fatalf("revoke failed: %+v", s.Rules)
	}
	if _, err := s.Allow(Rule{ID: "x", Ports: "nope", Label: "X"}); err != ErrPorts {
		t.Fatalf("bad ports gave %v", err)
	}
}

func TestFull(t *testing.T) {
	s := Default()
	var err error
	for i := 0; i < MaxRules; i++ {
		s, err = s.Allow(Rule{ID: "app-" + string(rune('a'+i/26)) + string(rune('a'+i%26)), Ports: "1000/tcp", Label: "App"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Allow(Rule{ID: "one-more", Ports: "1/tcp", Label: "App"}); err != ErrFull {
		t.Fatalf("got %v", err)
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := Default().Allow(Rule{ID: "ssh", Ports: "22/tcp", Label: "Remote Login"})
	s.Profile = Public
	s.Enabled = true
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Profile != Public || len(back.Rules) != 1 || back.Rules[0].Label != "Remote Login" || !back.Enabled {
		t.Fatalf("round trip %+v", back)
	}
	missing, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil || missing.Enabled || missing.Profile != Home {
		t.Fatalf("default %+v %v", missing, err)
	}
}

func TestSystemServices(t *testing.T) {
	shipped, local := t.TempDir(), t.TempDir()
	write := func(dir, name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(shipped, "sinty-core.json", `{"label": "Sinty Core", "ports": "7412/tcp,7413/udp"}`)
	write(shipped, "nearby.json", `{"label": "Nearby", "ports": "1714-1764/tcp,1714-1764/udp"}`)
	write(shipped, "broken.json", `{"label": "Broken", "ports": "80/sctp"}`)
	write(local, "nearby.json", `{"label": "Nearby", "ports": "1716/tcp,1716/udp", "public_too": true}`)

	sys := LoadServices(shipped, local, filepath.Join(local, "missing"))
	if len(sys) != 2 {
		t.Fatalf("services: %+v", sys)
	}
	byID := map[string]Rule{}
	for _, r := range sys {
		byID[r.ID] = r
	}
	if byID["sinty-core"].Ports != "7412/tcp,7413/udp" || byID["nearby"].Ports != "1716/tcp,1716/udp" || !byID["nearby"].PublicToo {
		t.Fatalf("services: %+v", sys)
	}

	s := Default()
	s.System = sys
	s, _ = s.Allow(Rule{ID: "ssh", Ports: "22/tcp", Label: "Remote Login"})
	if got := len(s.Active()); got != 3 {
		t.Fatalf("home profile keeps %d rules", got)
	}
	s.Profile = Public
	if a := s.Active(); len(a) != 1 || a[0].ID != "nearby" {
		t.Fatalf("public profile keeps %+v", a)
	}
	if _, err := s.Revoke("sinty-core"); !errors.Is(err, ErrSystem) {
		t.Fatalf("revoking a system service: %v", err)
	}
	if _, err := s.Allow(Rule{ID: "sinty-core", Ports: "1/tcp", Label: "x"}); !errors.Is(err, ErrSystem) {
		t.Fatalf("replacing a system service: %v", err)
	}
	if same, err := s.Allow(Rule{ID: "nearby", Ports: "1716/tcp,1716/udp", Label: "Nearby", PublicToo: true}); err != nil || len(same.Rules) != 1 {
		t.Fatalf("asking for what a system service opens: %v %+v", err, same.Rules)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil || len(back.Rules) != 1 || len(back.System) != 0 {
		t.Fatalf("saved state carries system services: %+v %v", back, err)
	}
}
