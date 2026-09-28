// Package alert handles alert de-duplication, cooldown, severity
// escalation and explainable repeat behaviour.
package alert

import (
	"fmt"
	"sync"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

// State tracks a single (client, feature) alert lifecycle.
type State struct {
	Alert         model.Alert
	FirstSeen     time.Time
	LastFiredAt   time.Time
	LastEvaluated time.Time
	FiredCount    int
	Suppressed    int
	CooldownUntil time.Time
	Active        bool
}

// Manager owns alert states. It is mutex-guarded so the detector can
// share it as needed; the normal fast path is single-goroutine per
// client shard.
type Manager struct {
	mu       sync.Mutex
	states   map[string]*State
	cooldown time.Duration
}

func NewManager(cooldown time.Duration) *Manager {
	return &Manager{states: make(map[string]*State), cooldown: cooldown}
}

// SetCooldown updates the cooldown duration used for future fires and
// reopen decisions; existing cooldown deadlines are unchanged.
func (m *Manager) SetCooldown(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cooldown = d
}

// Key uniquely identifies an alert identity: client + feature.
func Key(ip string, f model.FeatureKey) string {
	return ip + "|" + string(f)
}

// newID gives each newly raised alert a distinguishable identity.
func newID(ip string, f model.FeatureKey, at time.Time) string {
	return fmt.Sprintf("%s|%s|%d", ip, string(f), at.UnixNano())
}

// Decide records one evaluation and returns the resulting update, or
// nil when nothing should be delivered (condition absent and no active
// state existed).
//
// Semantics:
//   - condition absent (sev None / score below fireThreshold): active
//     state is deactivated; cooldown still applies to a re-raise so a
//     brief dip cannot be used to spam fresh alerts.
//   - no active firing & condition present -> AlertRaised.
//   - within cooldown, same severity & score profile ->
//     AlertRepeatedSuppressed (no new valid alert; counted).
//   - within cooldown, severity strictly increases ->
//     AlertSeverityChanged (a new, distinguishable alert).
//   - cooldown expired while condition persists -> AlertReopened with
//     a fresh alert ID (the repeat is explainable via FiredCount and
//     the cooldown window).
//   - a new FeatureKey has its own identity and always raises its own
//     first alert (dedup is per feature, not per client).
func (m *Manager) Decide(ip, name string, feature model.FeatureKey, score float64,
	sev model.Severity, fireThreshold float64, winFrom, winTo, now time.Time) *model.AlertUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := Key(ip, feature)
	st, exists := m.states[key]
	present := sev > model.SeverityNone && score >= fireThreshold

	if !exists {
		if !present {
			return nil
		}
		st = &State{FirstSeen: now}
		m.states[key] = st
	}
	st.LastEvaluated = now

	if !present {
		if st.Active {
			st.Active = false
		}
		return nil
	}

	mkAlert := func() model.Alert {
		return model.Alert{
			ID:         newID(ip, feature, now),
			ClientIP:   ip,
			Name:       name,
			Feature:    feature,
			Severity:   sev,
			Score:      score,
			WindowFrom: winFrom,
			WindowTo:   winTo,
			OpenedAt:   now,
			Message:    fmt.Sprintf("sustained dns-tunnel suspicion: client=%s feature=%s score=%.2f severity=%s", ip, string(feature), score, sev),
		}
	}

	if !st.Active {
		// Either the very first raise, or a re-raise after the
		// condition disappeared. Respect cooldown from last fire.
		if st.FiredCount > 0 && now.Before(st.CooldownUntil) {
			st.Suppressed++
			return &model.AlertUpdate{Kind: model.AlertRepeatedSuppressed, Alert: st.Alert, At: now}
		}
		kind := model.AlertRaised
		if st.FiredCount > 0 {
			kind = model.AlertReopened
		}
		st.Alert = mkAlert()
		st.Active = true
		st.LastFiredAt = now
		st.CooldownUntil = now.Add(m.cooldown)
		st.FiredCount++
		return &model.AlertUpdate{Kind: kind, Alert: st.Alert, At: now}
	}

	// Active and within a firing lifecycle.
	if now.Before(st.CooldownUntil) {
		if sev > st.Alert.Severity {
			prev := st.Alert.Severity
			st.Alert = mkAlert()
			st.Alert.Score = score
			st.LastFiredAt = now
			st.CooldownUntil = now.Add(m.cooldown)
			return &model.AlertUpdate{Kind: model.AlertSeverityChanged, Alert: st.Alert, Previous: prev, At: now}
		}
		st.Suppressed++
		return &model.AlertUpdate{Kind: model.AlertRepeatedSuppressed, Alert: st.Alert, At: now}
	}

	// Cooldown elapsed while the condition still persists: reopen,
	// producing a new distinguishable alert.
	st.Alert = mkAlert()
	st.LastFiredAt = now
	st.CooldownUntil = now.Add(m.cooldown)
	st.FiredCount++
	return &model.AlertUpdate{Kind: model.AlertReopened, Alert: st.Alert, At: now}
}

// Get returns the state for an identity, if any.
func (m *Manager) Get(ip string, f model.FeatureKey) (*State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.states[Key(ip, f)]
	return st, ok
}

// ActiveAlerts returns a snapshot of all active alerts.
func (m *Manager) ActiveAlerts() []model.Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.Alert, 0, len(m.states))
	for _, st := range m.states {
		if st.Active {
			out = append(out, st.Alert)
		}
	}
	return out
}

// SnapshotStates returns copies of all states (for persistence).
func (m *Manager) SnapshotStates() []State {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]State, 0, len(m.states))
	for _, st := range m.states {
		cp := *st
		out = append(out, cp)
	}
	return out
}

// LoadState installs a state, keyed by its alert identity.
func (m *Manager) LoadState(st State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[Key(st.Alert.ClientIP, st.Alert.Feature)] = &st
}

// Prune removes states that have been inactive since before cutoff and
// are outside their cooldown window.
func (m *Manager) Prune(cutoff time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for k, st := range m.states {
		if !st.Active && st.CooldownUntil.Before(cutoff) {
			delete(m.states, k)
			removed++
		}
	}
	return removed
}
