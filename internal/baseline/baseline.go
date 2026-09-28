// Package baseline maintains evolving per-client and per-query-name
// statistical baselines using exponentially weighted moving moments.
package baseline

import (
	"sort"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

// Stats holds an exponentially weighted mean/variance for one metric.
//
// Update rules (alpha = cfg.EWMAAlpha):
//
//	d    = x - mean
//	mean = mean + alpha*d
//	var  = (1-alpha)*(var + alpha*d*d)
//
// This lets the baseline drift with genuinely changing traffic instead of
// alarming forever on a permanent behavior change.
type Stats struct {
	N        int64     `json:"n"`
	Mean     float64   `json:"mean"`
	Var      float64   `json:"var"`
	LastSeen time.Time `json:"last_seen"`
}

func (s *Stats) observe(x, alpha float64) {
	if s.N == 0 {
		s.Mean = x
		s.Var = 0
	} else {
		d := x - s.Mean
		s.Mean += alpha * d
		s.Var = (1 - alpha) * (s.Var + alpha*d*d)
	}
	s.N++
}

// Stddev returns the running weighted standard deviation.
func (s *Stats) Stddev() float64 {
	if s.Var <= 0 {
		return 0
	}
	// sqrt via math import avoided with explicit helper
	return sqrt(s.Var)
}

func sqrt(x float64) float64 {
	// tiny Newton iteration, keeps imports local
	z := x
	for i := 0; i < 12; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}

// ClientBase is the per-client evolving baseline.
type ClientBase struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`

	NameLen     Stats `json:"name_len"`
	Entropy     Stats `json:"entropy"`
	Digit       Stats `json:"digit"`
	LongestLbl  Stats `json:"longest_label"`
	Intervals   Stats `json:"intervals"` // micros between consecutive queries
	RespLatency Stats `json:"resp_latency"`
	NXRate      Stats `json:"nx_rate"` // EWMA of 0/1
	NoAnsRate   Stats `json:"no_ans_rate"`

	lastQuery time.Time
}

// NameBase is the per-query-name baseline. Frequency is tracked per fixed
// bucket so that bursts and heartbeats are distinguishable.
type NameBase struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`

	Intervals Stats `json:"intervals"`

	bucketStart time.Time
	bucketHits  int64
	// QPS is updated with the completed bucket's rate (hits/bucketWidth).
	QPS Stats `json:"qps"`

	lastQuery time.Time
}

// BucketStart exposes the start of the in-progress frequency bucket.
func (n *NameBase) BucketStart() time.Time { return n.bucketStart }

// BucketHits returns the hits counted in the in-progress bucket.
func (n *NameBase) BucketHits() int64 { return n.bucketHits }

// Tracker maintains baselines keyed by client and by query name.
type Tracker struct {
	cfg         config.BaselineConfig
	bucketWidth time.Duration
	clients     map[string]*ClientBase
	names       map[string]*NameBase
}

// NewTracker constructs an empty tracker. bucketWidth is the frequency
// accounting bucket size (normally WindowConfig.Slide).
func NewTracker(cfg config.BaselineConfig, bucketWidth time.Duration) *Tracker {
	if cfg.EWMAAlpha <= 0 || cfg.EWMAAlpha > 1 {
		cfg.EWMAAlpha = 0.1
	}
	return &Tracker{
		cfg:         cfg,
		bucketWidth: bucketWidth,
		clients:     map[string]*ClientBase{},
		names:       map[string]*NameBase{},
	}
}

// Observe incorporates an event. It returns the interval in micros since
// the client's previous query (0 on the first observation). Frequency
// bucket boundaries are derived from cfg bucket width.
func (t *Tracker) Observe(e *model.Event, f model.Feature, ts time.Time) int64 {
	a := t.cfg.EWMAAlpha

	c := t.clients[e.ClientIP]
	if c == nil {
		c = &ClientBase{FirstSeen: ts}
		t.clients[e.ClientIP] = c
	}
	var gapMicros int64
	if !c.lastQuery.IsZero() {
		gapMicros = ts.Sub(c.lastQuery).Microseconds()
		if gapMicros >= 0 {
			c.Intervals.observe(float64(gapMicros), a)
		}
	}
	c.lastQuery = ts
	c.Count++
	c.LastSeen = ts
	c.NameLen.observe(float64(f.NameLen), a)
	c.Entropy.observe(f.Entropy, a)
	c.Digit.observe(f.DigitRatio, a)
	c.LongestLbl.observe(float64(f.LongestLabel), a)
	if f.HasResponse {
		nx := 0.0
		if f.NXDomain {
			nx = 1
		}
		c.NXRate.observe(nx, a)
		noAns := 0.0
		if f.AnsCount == 0 {
			noAns = 1
		}
		c.NoAnsRate.observe(noAns, a)
		if f.RespLatency > 0 {
			c.RespLatency.observe(float64(f.RespLatency), a)
		}
	}

	n := t.names[e.QName]
	if n == nil {
		n = &NameBase{FirstSeen: ts}
		t.names[e.QName] = n
	}
	if !n.lastQuery.IsZero() {
		if g := ts.Sub(n.lastQuery).Microseconds(); g >= 0 {
			n.Intervals.observe(float64(g), a)
		}
	}
	n.lastQuery = ts
	n.Count++
	n.LastSeen = ts

	// per-bucket frequency accounting
	if t.bucketWidth > 0 {
		bStart := ts.Truncate(t.bucketWidth)
		if n.bucketStart.IsZero() {
			n.bucketStart = bStart
		}
		if !bStart.Equal(n.bucketStart) {
			qps := float64(n.bucketHits) / t.bucketWidth.Seconds()
			n.QPS.observe(qps, a)
			n.bucketStart = bStart
			n.bucketHits = 0
		}
		n.bucketHits++
	}
	return gapMicros
}

// IsTrusted reports whether the client baseline has enough samples.
func (t *Tracker) IsTrusted(client string) bool {
	c := t.clients[client]
	return c != nil && c.Count >= int64(t.cfg.MinSamples)
}

// Client returns the client baseline or nil.
func (t *Tracker) Client(client string) *ClientBase { return t.clients[client] }

// Name returns the name baseline or nil.
func (t *Tracker) Name(qname string) *NameBase { return t.names[qname] }

// Evict removes baselines idle since cutoff and enforces the key cap.
// It returns the number of entries removed.
func (t *Tracker) Evict(cutoff time.Time) int {
	removed := 0
	for k, c := range t.clients {
		if c.LastSeen.Before(cutoff) {
			delete(t.clients, k)
			removed++
		}
	}
	for k, n := range t.names {
		if n.LastSeen.Before(cutoff) {
			delete(t.names, k)
			removed++
		}
	}
	removed += t.capMap(t.clients, t.cfg.MaxBaselineKeys)
	removed += t.capMapNames(t.cfg.MaxBaselineKeys)
	return removed
}

func t_capMap[V any](m map[string]V, capN int, lastSeen func(V) time.Time) int {
	if capN <= 0 || len(m) <= capN {
		return 0
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, lastSeen(v)})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	drop := len(m) - capN
	for i := 0; i < drop; i++ {
		delete(m, all[i].k)
	}
	return drop
}

func (t *Tracker) capMap(m map[string]*ClientBase, capN int) int {
	return t_capMap(m, capN, func(c *ClientBase) time.Time { return c.LastSeen })
}

func (t *Tracker) capMapNames(capN int) int {
	return t_capMap(t.names, capN, func(n *NameBase) time.Time { return n.LastSeen })
}

// Snapshot is a serializable baseline state.
type Snapshot struct {
	Clients map[string]*ClientBase `json:"clients"`
	Names   map[string]*NameBase   `json:"names"`
}

// Export returns the current state for persistence.
func (t *Tracker) Export() Snapshot {
	return Snapshot{Clients: t.clients, Names: t.names}
}

// Restore replaces state from a persisted snapshot.
func (t *Tracker) Restore(s Snapshot) {
	if s.Clients != nil {
		t.clients = s.Clients
	}
	if s.Names != nil {
		t.names = s.Names
	}
}

// LastQueryTime returns the timestamp of the client's most recent event.
func (c *ClientBase) LastQueryTime() time.Time { return c.lastQuery }
