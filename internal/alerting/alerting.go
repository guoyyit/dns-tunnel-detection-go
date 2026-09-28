// Package alerting implements alert deduplication, cooldown and severity
// escalation semantics.
//
// Identity of a tunnel behavior is (client IP, tunnel feature key). Within
// one cooldown window repeated evidence is suppressed (counted, not fired).
// A NEW distinguishable alert is produced when:
//
//  1. the identity is seen for the first time;
//  2. its cooldown has expired (repeat-after-cooldown is a fresh alert with
//     a new id and a reason explaining it);
//  3. severity escalates while the cooldown is active (optional).
//
// Alert ids embed first-seen timestamp and severity, so identical evidence
// replayed after a crash yields the same id and never double-fires.
package alerting

import (
	"fmt"
	"sort"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

// active tracks one currently open alert identity.
type active struct {
	Alert      model.Alert `json:"alert"`
	ExpireAt   time.Time   `json:"expire_at"`
	Reopened   int         `json:"reopened"`   // number of post-cooldown refires
	Suppressed int         `json:"suppressed"` // events swallowed during cooldown
}

// Manager is shard-local (single goroutine).
type Manager struct {
	cfg    config.CooldownConfig
	active map[string]*active
}

// Candidate is evidence evaluated against cooldown state.
type Candidate struct {
	Client     string
	Key        string
	Severity   model.Severity
	Score      float64
	TS         time.Time
	Reasons    []string
	SampleName string
}

// New constructs a manager.
func New(cfg config.CooldownConfig) *Manager {
	return &Manager{cfg: cfg, active: map[string]*active{}}
}

func id(client, key string, firstTS time.Time, sev model.Severity) string {
	return fmt.Sprintf("%s|%s|%d|%s", client, key, firstTS.UnixNano(), sev)
}

// Consider returns a non-nil Alert when the candidate creates a new
// distinguishable alert, otherwise nil (suppressed and counted).
func (m *Manager) Consider(c Candidate) *model.Alert {
	a := m.active[c.Client+"\x00"+c.Key]

	// Case 2: cooldown expired -> new alert, explain the reopen.
	if a != nil && !a.ExpireAt.IsZero() && !c.TS.Before(a.ExpireAt) {
		a.Reopened++
		a.Suppressed = 0
		a.Alert = model.Alert{
			ID:         id(c.Client, c.Key, c.TS, c.Severity),
			ClientIP:   c.Client,
			TunnelKey:  c.Key,
			Severity:   c.Severity,
			Score:      c.Score,
			FirstTS:    c.TS,
			FireTS:     c.TS,
			LastTS:     c.TS,
			Reasons:    withReopen(c.Reasons, a.Reopened),
			SampleName: c.SampleName,
		}
		a.ExpireAt = c.TS.Add(m.cfg.Duration)
		return &a.Alert
	}

	// Case 3: severity escalation inside active cooldown.
	if a != nil && m.cfg.SeverityEscalate && c.Severity > a.Alert.Severity {
		a.Alert = model.Alert{
			ID:         id(c.Client, c.Key, a.Alert.FirstTS, c.Severity),
			ClientIP:   c.Client,
			TunnelKey:  c.Key,
			Severity:   c.Severity,
			Score:      c.Score,
			FirstTS:    a.Alert.FirstTS,
			FireTS:     c.TS,
			LastTS:     c.TS,
			Reasons:    withEscalation(c.Reasons, a.Alert.Severity, c.Severity),
			SampleName: c.SampleName,
		}
		a.ExpireAt = c.TS.Add(m.cfg.Duration) // escalation restarts cooldown
		return &a.Alert
	}

	if a != nil {
		// Suppressed during cooldown (or no escalation).
		a.Suppressed++
		a.Alert.LastTS = c.TS
		if c.Score > a.Alert.Score {
			a.Alert.Score = c.Score
		}
		return nil
	}

	// Case 1: brand-new identity.
	al := model.Alert{
		ID:         id(c.Client, c.Key, c.TS, c.Severity),
		ClientIP:   c.Client,
		TunnelKey:  c.Key,
		Severity:   c.Severity,
		Score:      c.Score,
		FirstTS:    c.TS,
		FireTS:     c.TS,
		LastTS:     c.TS,
		Reasons:    c.Reasons,
		SampleName: c.SampleName,
	}
	m.active[c.Client+"\x00"+c.Key] = &active{
		Alert:    al,
		ExpireAt: c.TS.Add(m.cfg.Duration),
	}
	out := al
	return &out
}

func withReopen(reasons []string, n int) []string {
	out := append([]string{}, reasons...)
	out = append(out, fmt.Sprintf("cooldown_expired_refire#%d", n))
	sort.Strings(out)
	return out
}

func withEscalation(reasons []string, old, neu model.Severity) []string {
	out := append([]string{}, reasons...)
	out = append(out, fmt.Sprintf("severity_escalation:%s->%s", old, neu))
	sort.Strings(out)
	return out
}

// Suppressed returns how many candidates were suppressed for an identity.
func (m *Manager) Suppressed(client, key string) int {
	if a := m.active[client+"\x00"+key]; a != nil {
		return a.Suppressed
	}
	return 0
}

// Expire removes identities whose cooldown elapsed strictly before ts.
// Expired identities are deleted (not merely marked): the NEXT candidate
// after expiry then transparently follows the reopen path. Removing them
// early keeps memory bounded.
func (m *Manager) Expire(ts time.Time) int {
	n := 0
	for k, a := range m.active {
		if !a.ExpireAt.IsZero() && !ts.Before(a.ExpireAt) {
			delete(m.active, k)
			n++
		}
	}
	m.cap()
	return n
}

func (m *Manager) cap() {
	if m.cfg.MaxActiveKeys <= 0 || len(m.active) <= m.cfg.MaxActiveKeys {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(m.active))
	for k, a := range m.active {
		all = append(all, kv{k, a.ExpireAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	drop := len(all) - m.cfg.MaxActiveKeys
	for i := 0; i < drop; i++ {
		delete(m.active, all[i].k)
	}
}

// Snap is a serializable alert-state snapshot.
type Snap struct {
	Active []*active `json:"active"`
}

// Export serializes state.
func (m *Manager) Export() Snap {
	out := Snap{Active: make([]*active, 0, len(m.active))}
	for _, a := range m.active {
		out.Active = append(out.Active, a)
	}
	sort.Slice(out.Active, func(i, j int) bool {
		return out.Active[i].Alert.ID < out.Active[j].Alert.ID
	})
	return out
}

// Restore rebuilds state.
func (m *Manager) Restore(s Snap) {
	m.active = map[string]*active{}
	for _, a := range s.Active {
		m.active[a.Alert.ClientIP+"\x00"+a.Alert.TunnelKey] = a
	}
}

// SetConfig swaps cooldown tuning without clearing active identities.
func (m *Manager) SetConfig(cfg config.CooldownConfig) { m.cfg = cfg }
