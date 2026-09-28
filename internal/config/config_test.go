package config

import "testing"

func TestExemptName(t *testing.T) {
	snap, err := WhitelistConfig{
		Suffixes: []string{"example.com", ".Updates.Example.ORG"},
		Regexps:  []string{`^hb-[0-9]+\.heartbeat\.internal$`},
		Clients:  []string{"10.0.0.1"},
	}.Compile(1)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"a.example.com":             true,
		"example.com.":              true,
		"notexample.com":            false,
		"x.updates.example.org":     true,
		"hb-123.heartbeat.internal": true,
		"hb-abc.heartbeat.internal": false,
	}
	for name, want := range cases {
		if got := snap.ExemptName(name); got != want {
			t.Errorf("ExemptName(%q)=%v want %v", name, got, want)
		}
	}
	if !snap.ExemptClient("10.0.0.1") {
		t.Error("client exemption failed")
	}
}

func TestBadRegexp(t *testing.T) {
	if _, err := (WhitelistConfig{Regexps: []string{"["}}).Compile(1); err == nil {
		t.Fatal("expected regexp compile error")
	}
}
