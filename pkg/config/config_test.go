package config

import "testing"

func TestHasSuffixDomain(t *testing.T) {
	cases := []struct {
		name, suffix string
		want         bool
	}{
		{"a.b.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"EXAMPLE.COM.", "example.com", true},
		{"notexample.com", "example.com", false},
		{"evil.com", "example.com", false},
	}
	for _, c := range cases {
		if got := hasSuffixDomain(c.name, c.suffix); got != c.want {
			t.Errorf("hasSuffixDomain(%q,%q)=%v want %v", c.name, c.suffix, got, c.want)
		}
	}
}

func TestWhitelistAndExemption(t *testing.T) {
	c := Default()
	c.Whitelist = []Rule{
		{NameSuffix: "corp.example.com"},
		{ClientIP: "9.9.9.9", NameSuffix: "admin.test"},
	}
	c.Exemptions = []Rule{
		{NameSuffix: "heartbeat.internal", Heartbeat: true},
		{NameRegexp: `^hb[0-9]+\.test$`},
	}
	s, err := c.Snapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsWhitelisted("1.1.1.1", "host.corp.example.com") {
		t.Fatal("subdomain should be whitelisted")
	}
	if s.IsWhitelisted("1.1.1.1", "corp.example.com.evil.com") {
		t.Fatal("look-alike suffix must not match")
	}
	if !s.IsWhitelisted("9.9.9.9", "admin.test") {
		t.Fatal("client-scoped whitelist must match that client")
	}
	if s.IsWhitelisted("8.8.8.8", "admin.test") {
		t.Fatal("client-scoped whitelist must not match other clients")
	}
	if !s.IsExempt("1.1.1.1", "hb123.test") {
		t.Fatal("regexp exemption should match")
	}
	if s.IsExempt("1.1.1.1", "hb.testx") {
		t.Fatal("anchored regexp must not match")
	}
}

func TestStoreReplacesAndBumpsGeneration(t *testing.T) {
	st, err := NewStore(Default())
	if err != nil {
		t.Fatal(err)
	}
	g1 := st.Current().Generation()
	c2 := Default()
	c2.Whitelist = []Rule{{NameSuffix: "new.test"}}
	if err := st.Replace(c2); err != nil {
		t.Fatal(err)
	}
	g2 := st.Current().Generation()
	if g2 <= g1 {
		t.Fatalf("generation must increase: %d -> %d", g1, g2)
	}
	if !st.Current().IsWhitelisted("1.1.1.1", "x.new.test") {
		t.Fatal("new snapshot rules must apply")
	}
}

func TestInvalidRegexpRejected(t *testing.T) {
	c := Default()
	c.Exemptions = []Rule{{NameRegexp: "("}}
	if _, err := c.Snapshot(1); err == nil {
		t.Fatal("invalid regexp must return an error")
	}
	st, _ := NewStore(Default())
	if err := st.Replace(c); err == nil {
		t.Fatal("Replace with invalid regexp must fail and keep old config")
	}
	if st.Current().Generation() != 1 {
		t.Fatal("failed replace must not bump generation")
	}
}

func TestSnapshotImmutability(t *testing.T) {
	c := Default()
	s, _ := c.Snapshot(1)
	// Mutating the source config must not change an already-held snapshot.
	c.Thresholds.MinSuspicionScore = 999
	if s.Raw().Thresholds.MinSuspicionScore == 999 {
		t.Fatal("snapshot must remain stable after source mutation")
	}
}
