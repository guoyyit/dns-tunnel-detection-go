// Package window implements deterministic sliding-window suspicion
// accumulation per (client, tunnel-feature) key.
//
// Time is bucketed by truncating the *event timestamp* to WindowConfig.Slide
// boundaries. Consequently window progression depends only on input event
// times, never on wall-clock scheduling, and is fully reproducible: the
// same event sequence always yields the same alerts.
package window

import (
	"sort"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
)

// bkt holds aggregated evidence inside one slide interval.
type bkt struct {
	Start   time.Time `json:"start"`
	Score   float64   `json:"score"`
	Hits    int       `json:"hits"`
	Samples int       `json:"samples"`
	Reasons []string  `json:"reasons,omitempty"`
}

func (b *bkt) addReason(r string) {
	for _, x := range b.Reasons {
		if x == r {
			return
		}
	}
	b.Reasons = append(b.Reasons, r)
}

// State tracks suspicion for one tunnel feature within one client.
type State struct {
	Client     string    `json:"client"`
	Key        string    `json:"key"`
	Buckets    []*bkt    `json:"buckets"`
	FirstTS    time.Time `json:"first_ts"`
	LastTS     time.Time `json:"last_ts"`
	SampleName string    `json:"sample_name,omitempty"`
}

func (s *State) upsertBucket(start time.Time) *bkt {
	i := sort.Search(len(s.Buckets), func(i int) bool {
		return !s.Buckets[i].Start.Before(start)
	})
	if i < len(s.Buckets) && s.Buckets[i].Start.Equal(start) {
		return s.Buckets[i]
	}
	b := &bkt{Start: start}
	s.Buckets = append(s.Buckets, nil)
	copy(s.Buckets[i+1:], s.Buckets[i:])
	s.Buckets[i] = b
	return b
}

// Window manages all sliding states; one instance per engine shard and
// therefore no internal locking.
type Window struct {
	cfg       config.WindowConfig
	states    map[string]*State
	watermark time.Time
}

// Decision is the evaluation result for a state.
type Decision struct {
	Fire       bool
	Severity   int
	Score      float64
	Active     int
	Client     string
	Key        string
	FirstTS    time.Time
	LastTS     time.Time
	SampleName string
	Reasons    []string
}

// New constructs an empty window.
func New(cfg config.WindowConfig) *Window {
	return &Window{
		cfg:    cfg,
		states: map[string]*State{},
	}
}

func stateID(client, key string) string { return client + "\x00" + key }

// Add records evidence at the event time. It reports whether the event was
// accepted. An event is rejected only when it is older than
// watermark - (window size + lateness grace), i.e. the buckets it belongs
// to have already been finalized and discarded. Such events can no longer
// influence any decision, so silently dropping them keeps state bounded and
// deterministic.
func (w *Window) Add(client, key string, ts time.Time, score float64, reasons []string, sample string) bool {
	if ts.After(w.watermark) {
		w.watermark = ts
	}
	cutoff := w.watermark.Add(-(w.cfg.Size + w.cfg.LatenessGrace))
	if ts.Before(cutoff) {
		return false
	}
	start := ts.Truncate(w.cfg.Slide)
	id := stateID(client, key)
	st := w.states[id]
	if st == nil {
		st = &State{Client: client, Key: key, FirstTS: ts}
		w.states[id] = st
	}
	if st.SampleName == "" {
		st.SampleName = sample
	}
	if ts.Before(st.FirstTS) {
		st.FirstTS = ts
	}
	if ts.After(st.LastTS) {
		st.LastTS = ts
		if sample != "" {
			st.SampleName = sample
		}
	}
	b := st.upsertBucket(start)
	b.Score += score
	if b.Score > w.cfg.MaxSuspectScore {
		b.Score = w.cfg.MaxSuspectScore
	}
	b.Hits++
	b.Samples++
	for _, r := range reasons {
		b.addReason(r)
	}
	return true
}

// Evaluate accumulates buckets fully inside the window ending at the given
// time and returns a decision per state. A state fires only when BOTH the
// total score and the number of active (non-trivial) buckets cross their
// thresholds, so a single isolated anomaly can never alert.
func (w *Window) Evaluate(ts time.Time) []Decision {
	horizon := ts.Add(-w.cfg.Size)
	if ts.After(w.watermark) {
		w.watermark = ts
	}
	out := make([]Decision, 0, len(w.states))
	for _, st := range w.states {
		var total float64
		active := 0
		reasons := map[string]struct{}{}
		for _, b := range st.Buckets {
			if b.Start.Before(horizon) || b.Start.After(ts) {
				continue
			}
			total += b.Score
			if b.Score > 0 {
				active++
			}
			for _, r := range b.Reasons {
				reasons[r] = struct{}{}
			}
		}
		rs := make([]string, 0, len(reasons))
		for r := range reasons {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		d := Decision{
			Score:      total,
			Active:     active,
			Client:     st.Client,
			Key:        st.Key,
			FirstTS:    st.FirstTS,
			LastTS:     st.LastTS,
			SampleName: st.SampleName,
			Reasons:    rs,
		}
		d.Fire = total >= w.cfg.FireScore && active >= w.cfg.FireBuckets
		if d.Fire {
			d.Severity = severityFor(total, active, w.cfg)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Client != out[j].Client {
			return out[i].Client < out[j].Client
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func severityFor(score float64, active int, cfg config.WindowConfig) int {
	// Relative strength beyond the fire threshold drives severity.
	r := score / cfg.FireScore
	switch {
	case r >= 2.0 || active >= len_factor(cfg):
		return 4 // critical
	case r >= 1.5:
		return 3 // high
	case r >= 1.2:
		return 2 // medium
	default:
		return 1 // low
	}
}

func len_factor(cfg config.WindowConfig) int {
	n := int(cfg.Size / cfg.Slide)
	if n <= 0 {
		return cfg.FireBuckets * 3
	}
	return n // active in nearly every bucket of the window
}

// Advance drops buckets older than ts - window size and removes states that
// became empty. It returns the number of states removed.
func (w *Window) Advance(ts time.Time) int {
	if ts.After(w.watermark) {
		w.watermark = ts
	}
	horizon := ts.Add(-w.cfg.Size)
	removed := 0
	for id, st := range w.states {
		keep := st.Buckets[:0]
		for _, b := range st.Buckets {
			if !b.Start.Before(horizon) {
				keep = append(keep, b)
			}
		}
		st.Buckets = keep
		if len(st.Buckets) == 0 {
			delete(w.states, id)
			removed++
		}
	}
	return removed
}

// Watermark returns the highest event timestamp accepted so far.
func (w *Window) Watermark() time.Time { return w.watermark }

// Snap is a serializable window snapshot.
type Snap struct {
	States []*State `json:"states"`
}

// Export serializes window state.
func (w *Window) Export() Snap {
	out := Snap{States: make([]*State, 0, len(w.states))}
	for _, st := range w.states {
		sort.Slice(st.Buckets, func(i, j int) bool { return st.Buckets[i].Start.Before(st.Buckets[j].Start) })
		out.States = append(out.States, st)
	}
	sort.Slice(out.States, func(i, j int) bool {
		if out.States[i].Client != out.States[j].Client {
			return out.States[i].Client < out.States[j].Client
		}
		return out.States[i].Key < out.States[j].Key
	})
	return out
}

// Restore rebuilds window state from a snapshot, re-sorting buckets and
// recomputing the watermark from the newest bucket.
func (w *Window) Restore(s Snap) {
	w.states = map[string]*State{}
	var max time.Time
	for _, st := range s.States {
		sort.Slice(st.Buckets, func(i, j int) bool { return st.Buckets[i].Start.Before(st.Buckets[j].Start) })
		w.states[stateID(st.Client, st.Key)] = st
		if len(st.Buckets) > 0 {
			if last := st.Buckets[len(st.Buckets)-1].Start; last.After(max) {
				max = last
			}
		}
	}
	w.watermark = max
}

// SetConfig swaps tuning parameters without discarding accumulated state.
// In-flight buckets continue to be interpreted under the new thresholds;
// callers that need strict generational separation rely on bucket expiry.
func (w *Window) SetConfig(cfg config.WindowConfig) { w.cfg = cfg }
