// Package window implements deterministic sliding-window accumulation
// of per-bucket suspicion scores with bounded out-of-order tolerance.
package window

import (
	"sort"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

// Bucket aggregates anomaly scores for one fixed-width time slice.
type Bucket struct {
	Index int64
	Start time.Time
	Count int64
	// Max keeps the strongest per-feature weighted anomaly observed in
	// the bucket; Sum accumulates weighted strength.
	Max map[string]float64
	Sum map[string]float64
	// Raw keeps the strongest per-feature anomaly *before* weighting,
	// used by the multi-feature gate (the gate must not depend on how a
	// feature happens to be weighted).
	Raw map[string]float64
}

func newBucket(index int64, start time.Time) *Bucket {
	return &Bucket{
		Index: index,
		Start: start,
		Max:   make(map[string]float64),
		Sum:   make(map[string]float64),
		Raw:   make(map[string]float64),
	}
}

// score is this bucket's combined anomaly score: per-feature max
// (so one strong query is enough) summed across features.
func (b *Bucket) score() float64 {
	total := 0.0
	for _, v := range b.Max {
		total += v
	}
	return total
}

// Evaluation is the result of evaluating the buckets currently in a
// window.
type Evaluation struct {
	Score float64
	// Sustained is the longest run of consecutive anomalous buckets
	// (score >= threshold) inside the window.
	Sustained int
	// ActiveFeatures are the features contributing to the score.
	ActiveFeatures []model.FeatureKey
	From           time.Time
	To             time.Time
}

// Window keeps the most recent depth buckets for one (client, name)
// series. Advancement is purely a function of the supplied watermark,
// so identical event streams and watermarks always yield identical
// state: late events up to lateBuckets behind the horizon fold into
// existing buckets; older events are rejected.
type Window struct {
	ClientIP string
	Name     string

	width       time.Duration
	depth       int
	lateBuckets int64
	cfgGen      int64
	buckets     map[int64]*Bucket
	lowest      int64
	highest     int64
}

// NewWindow creates a window. depth = window size / bucket width;
// lateBuckets is how many finalized buckets behind the horizon still
// accept late arrivals.
func NewWindow(clientIP, name string, width time.Duration, depth, lateBuckets int, cfgGen int64) *Window {
	if depth < 1 {
		depth = 1
	}
	if lateBuckets < 0 {
		lateBuckets = 0
	}
	return &Window{
		ClientIP:    clientIP,
		Name:        name,
		width:       width,
		depth:       depth,
		lateBuckets: int64(lateBuckets),
		cfgGen:      cfgGen,
		buckets:     make(map[int64]*Bucket),
	}
}

// CfgGen returns the configuration generation the window was created
// under.
func (w *Window) CfgGen() int64 { return w.cfgGen }

// Add folds one scored observation into its timestamp bucket.
// It returns false when the event is older than the late-tolerance
// horizon or newer gaps are lazily bridged (empty buckets count as
// non-anomalous).
func (w *Window) Add(at time.Time, featureScores, rawScores map[string]float64) bool {
	idx := BucketIndex(at, w.width)
	// Reject events behind the ingestion horizon. The horizon is a
	// deterministic function of the highest observed bucket, the depth
	// and the late tolerance; it only moves forward as newer events
	// arrive or Advance is driven by a watermark. Filling an
	// earlier-than-lowest bucket out of order (within tolerance) is
	// accepted, because lowest tracks retained contents, not the floor.
	if w.highest != 0 {
		floor := w.highest - int64(w.depth) + 1 - w.lateBuckets
		if idx < floor {
			return false
		}
	}
	b, ok := w.buckets[idx]
	if !ok {
		b = newBucket(idx, BucketStart(idx, w.width))
		w.buckets[idx] = b
	}
	if len(w.buckets) == 1 {
		w.lowest, w.highest = idx, idx
	} else {
		if idx < w.lowest {
			w.lowest = idx
		}
		if idx > w.highest {
			w.highest = idx
		}
	}
	b.Count++
	for feat, val := range featureScores {
		if val <= 0 {
			continue
		}
		if val > b.Max[feat] {
			b.Max[feat] = val
		}
		b.Sum[feat] += val
	}
	for feat, val := range rawScores {
		if val <= 0 {
			continue
		}
		if val > b.Raw[feat] {
			b.Raw[feat] = val
		}
	}
	return true
}

// Advance closes and evicts buckets that have fully left the window
// relative to watermark and returns the evicted bucket indexes.
// The kept horizon is [watermarkIdx-depth+1-lateBuckets, watermarkIdx]
// for ingestion; evaluation only counts the depth most recent buckets.
func (w *Window) Advance(watermark time.Time) []int64 {
	wm := BucketIndex(watermark, w.width)
	// Horizon floor includes late tolerance so late events can still
	// land in recently finalized buckets.
	floor := wm - int64(w.depth) + 1 - w.lateBuckets
	var evicted []int64
	for idx := range w.buckets {
		if idx < floor {
			evicted = append(evicted, idx)
			delete(w.buckets, idx)
		}
	}
	sort.Slice(evicted, func(i, j int) bool { return evicted[i] < evicted[j] })
	// Recompute lowest/highest from retained buckets.
	first := true
	for idx := range w.buckets {
		if first {
			w.lowest, w.highest, first = idx, idx, false
			continue
		}
		if idx < w.lowest {
			w.lowest = idx
		}
		if idx > w.highest {
			w.highest = idx
		}
	}
	if first {
		w.lowest, w.highest = 0, 0
	}
	return evicted
}

// LowestIndex returns the current lowest retained bucket index (0 if empty).
func (w *Window) LowestIndex() int64 { return w.lowest }

// HighestIndex returns the current highest retained bucket index (0 if empty).
func (w *Window) HighestIndex() int64 { return w.highest }

// Evaluate inspects the depth most recent buckets up to the highest
// observed bucket and aggregates suspicion. Buckets missing from the
// map count as empty (score 0), so gaps act as non-anomalous time.
func (w *Window) Evaluate(threshold float64) Evaluation {
	ev := Evaluation{}
	if len(w.buckets) == 0 {
		return ev
	}
	hi := w.highest
	lo := hi - int64(w.depth) + 1
	if l := w.lowest; l > lo {
		lo = l
	}
	featureSeen := make(map[string]bool)
	indexes := make([]int64, 0, w.depth)
	scoreSum := 0.0
	anomalous := make([]bool, 0, w.depth)
	for idx := lo; idx <= hi; idx++ {
		b, ok := w.buckets[idx]
		indexes = append(indexes, idx)
		if !ok {
			anomalous = append(anomalous, false)
			continue
		}
		sc := b.score()
		scoreSum += sc
		for f := range b.Max {
			featureSeen[f] = true
		}
		anomalous = append(anomalous, sc >= threshold)
	}
	// Longest consecutive run of anomalous buckets.
	run, best := 0, 0
	for _, a := range anomalous {
		if a {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 0
		}
	}
	ev.Sustained = best
	n := len(indexes)
	if n > 0 {
		ev.Score = scoreSum / float64(n)
		ev.From = BucketStart(indexes[0], w.width)
		ev.To = BucketStart(indexes[n-1], w.width).Add(w.width)
	}
	feats := make([]string, 0, len(featureSeen))
	for f := range featureSeen {
		feats = append(feats, f)
	}
	sort.Strings(feats)
	for _, f := range feats {
		ev.ActiveFeatures = append(ev.ActiveFeatures, model.FeatureKey(f))
	}
	return ev
}

// Buckets returns a snapshot copy of retained buckets (for persistence).
func (w *Window) Buckets() []Bucket {
	out := make([]Bucket, 0, len(w.buckets))
	for _, b := range w.buckets {
		cp := Bucket{Index: b.Index, Start: b.Start, Count: b.Count,
			Max: make(map[string]float64, len(b.Max)),
			Sum: make(map[string]float64, len(b.Sum)),
			Raw: make(map[string]float64, len(b.Raw))}
		for k, v := range b.Max {
			cp.Max[k] = v
		}
		for k, v := range b.Sum {
			cp.Sum[k] = v
		}
		for k, v := range b.Raw {
			cp.Raw[k] = v
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// LoadBuckets restores buckets from a snapshot.
func (w *Window) LoadBuckets(bs []Bucket) {
	w.buckets = make(map[int64]*Bucket, len(bs))
	first := true
	for _, b := range bs {
		cp := newBucket(b.Index, b.Start)
		cp.Count = b.Count
		for k, v := range b.Max {
			cp.Max[k] = v
		}
		for k, v := range b.Sum {
			cp.Sum[k] = v
		}
		for k, v := range b.Raw {
			cp.Raw[k] = v
		}
		w.buckets[b.Index] = cp
		if first {
			w.lowest, w.highest, first = b.Index, b.Index, false
			continue
		}
		if b.Index < w.lowest {
			w.lowest = b.Index
		}
		if b.Index > w.highest {
			w.highest = b.Index
		}
	}
	if first {
		w.lowest, w.highest = 0, 0
	}
}

// BucketIndex maps a timestamp to a deterministic bucket index using
// the Unix epoch as the fixed origin (UTC, independent of time zones).
func BucketIndex(t time.Time, width time.Duration) int64 {
	return t.UnixNano() / int64(width)
}

// BucketStart maps a bucket index back to its start time using the
// Unix epoch as the fixed origin (UTC, independent of time zones).
func BucketStart(index int64, width time.Duration) time.Time {
	return time.Unix(0, 0).UTC().Add(time.Duration(index) * width)
}
