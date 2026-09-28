package alerting

import (
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

func mgr() *Manager {
	cfg := config.Default().Cooldown
	cfg.Duration = time.Minute
	return New(cfg)
}

func cand(ts time.Time, sev model.Severity) Candidate {
	return Candidate{Client: "c1", Key: "evil.com", Severity: sev, Score: 7, TS: ts}
}

func TestDedupWithinCooldown(t *testing.T) {
	m := mgr()
	t0 := time.Unix(1000, 0)
	a1 := m.Consider(cand(t0, model.SeverityLow))
	if a1 == nil {
		t.Fatal("first must fire")
	}
	if m.Consider(cand(t0.Add(10*time.Second), model.SeverityLow)) != nil {
		t.Fatal("repeat within cooldown must be suppressed")
	}
	if m.Suppressed("c1", "evil.com") != 1 {
		t.Fatal("suppressed counter wrong")
	}
}

func TestSeverityEscalationFires(t *testing.T) {
	m := mgr()
	t0 := time.Unix(1000, 0)
	a1 := m.Consider(cand(t0, model.SeverityLow))
	a2 := m.Consider(cand(t0.Add(20*time.Second), model.SeverityHigh))
	if a2 == nil || a2.ID == a1.ID {
		t.Fatal("escalation must produce a distinct alert")
	}
	// de-escalation is suppressed
	if m.Consider(cand(t0.Add(30*time.Second), model.SeverityLow)) != nil {
		t.Fatal("de-escalation must be suppressed")
	}
}

func TestRefireAfterCooldownExplained(t *testing.T) {
	m := mgr()
	t0 := time.Unix(1000, 0)
	a1 := m.Consider(cand(t0, model.SeverityLow))
	a2 := m.Consider(cand(t0.Add(2*time.Minute), model.SeverityLow))
	if a2 == nil || a2.ID == a1.ID {
		t.Fatal("post-cooldown repeat must be a new alert")
	}
	found := false
	for _, r := range a2.Reasons {
		if r == "cooldown_expired_refire#1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("refire reason missing: %v", a2.Reasons)
	}
}

func TestExpireDeletes(t *testing.T) {
	m := mgr()
	t0 := time.Unix(1000, 0)
	m.Consider(cand(t0, model.SeverityLow))
	if n := m.Expire(t0.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("expired=%d want 1", n)
	}
	a := m.Consider(cand(t0.Add(2*time.Minute), model.SeverityLow))
	if a == nil {
		t.Fatal("fresh alert expected after expiry deletion")
	}
}

func TestNewFeatureDistinct(t *testing.T) {
	m := mgr()
	t0 := time.Unix(1000, 0)
	a := m.Consider(cand(t0, model.SeverityLow))
	b := m.Consider(Candidate{Client: "c1", Key: "other.net", Severity: model.SeverityLow, TS: t0})
	if b == nil || b.TunnelKey == a.TunnelKey {
		t.Fatal("different tunnel key must alert independently")
	}
}

func TestRestoreKeepsCooldown(t *testing.T) {
	m := mgr()
	t0 := time.Unix(1000, 0)
	m.Consider(cand(t0, model.SeverityLow))
	snap := m.Export()
	m2 := mgr()
	m2.Restore(snap)
	if m2.Consider(cand(t0.Add(30*time.Second), model.SeverityLow)) != nil {
		t.Fatal("restored cooldown must still suppress")
	}
}
