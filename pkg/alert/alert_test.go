package alert

import (
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

var t0 = time.Unix(1_700_000_000, 0).UTC()

const win = time.Minute
const fire = 2.0

func decide(m *Manager, at time.Time, sev model.Severity, score float64) *model.AlertUpdate {
	return m.Decide("c", "z.test", "tunnel", score, sev, fire, t0, t0.Add(win), at)
}

func TestRaiseSuppressReopen(t *testing.T) {
	m := NewManager(10 * time.Minute)

	// Below threshold -> nothing.
	if u := decide(m, t0, model.SeverityMedium, 1.0); u != nil {
		t.Fatal("below threshold must not raise")
	}
	// First raise.
	u := decide(m, t0, model.SeverityMedium, 3)
	if u == nil || u.Kind != model.AlertRaised {
		t.Fatalf("expected raised, got %v", u)
	}
	firstID := u.Alert.ID

	// Repeat within cooldown, same severity -> suppressed, same ID.
	u = decide(m, t0.Add(time.Minute), model.SeverityMedium, 3)
	if u == nil || u.Kind != model.AlertRepeatedSuppressed {
		t.Fatalf("expected suppressed, got %v", u)
	}
	if u.Alert.ID != firstID {
		t.Fatal("suppressed repeat must keep the same valid alert ID")
	}
	st, _ := m.Get("c", "tunnel")
	if st.Suppressed != 1 {
		t.Fatalf("suppressed count = %d", st.Suppressed)
	}

	// After cooldown with condition persisting -> reopen, new ID.
	u = decide(m, t0.Add(11*time.Minute), model.SeverityMedium, 3)
	if u == nil || u.Kind != model.AlertReopened {
		t.Fatalf("expected reopened, got %v", u)
	}
	if u.Alert.ID == firstID {
		t.Fatal("reopen must produce a distinguishable new alert ID")
	}
}

func TestSeverityEscalationWithinCooldown(t *testing.T) {
	m := NewManager(10 * time.Minute)
	u := decide(m, t0, model.SeverityMedium, 3)
	id := u.Alert.ID
	u = decide(m, t0.Add(time.Minute), model.SeverityHigh, 4.5)
	if u == nil || u.Kind != model.AlertSeverityChanged {
		t.Fatalf("severity increase must escalate, got %v", u)
	}
	if u.Previous != model.SeverityMedium || u.Alert.Severity != model.SeverityHigh {
		t.Fatal("escalation must record previous and new severity")
	}
	if u.Alert.ID == id {
		t.Fatal("escalation must create a new distinguishable alert")
	}
	// A later equal/lower severity inside cooldown is suppressed.
	u = decide(m, t0.Add(2*time.Minute), model.SeverityHigh, 4.6)
	if u.Kind != model.AlertRepeatedSuppressed {
		t.Fatalf("same severity must suppress, got %v", u)
	}
}

func TestNewFeatureIndependent(t *testing.T) {
	m := NewManager(10 * time.Minute)
	a := m.Decide("c", "z", model.FeatureKey("tunnel"), 3, model.SeverityMedium, fire, t0, t0.Add(win), t0)
	b := m.Decide("c", "z", model.FeatureKey("beacon"), 3, model.SeverityMedium, fire, t0, t0.Add(win), t0)
	if a == nil || b == nil || a.Alert.ID == b.Alert.ID {
		t.Fatal("distinct features must raise independent first alerts")
	}
	if len(m.ActiveAlerts()) != 2 {
		t.Fatalf("expected 2 active alerts, got %d", len(m.ActiveAlerts()))
	}
}

func TestConditionClearsThenRespectsCooldown(t *testing.T) {
	m := NewManager(10 * time.Minute)
	decide(m, t0, model.SeverityMedium, 3)                // raise
	decide(m, t0.Add(time.Minute), model.SeverityNone, 0) // clears
	if len(m.ActiveAlerts()) != 0 {
		t.Fatal("cleared condition must deactivate")
	}
	// Reappear still inside cooldown -> suppressed (no double alert).
	u := decide(m, t0.Add(2*time.Minute), model.SeverityMedium, 3)
	if u == nil || u.Kind != model.AlertRepeatedSuppressed {
		t.Fatalf("re-raise inside cooldown must suppress, got %v", u)
	}
}

func TestPrune(t *testing.T) {
	m := NewManager(time.Minute)
	decide(m, t0, model.SeverityMedium, 3)
	decide(m, t0.Add(time.Second), model.SeverityNone, 0) // inactive, cd=t0+1m
	removed := m.Prune(t0.Add(2 * time.Minute))
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
}
