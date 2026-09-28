package window

import (
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

var epoch = time.Unix(0, 0).UTC()

func at(sec int64) time.Time { return epoch.Add(time.Duration(sec) * time.Second) }

func TestBucketIndexDeterministic(t *testing.T) {
	w := 30 * time.Second
	i1 := BucketIndex(at(60), w)
	i2 := BucketIndex(at(89), w)
	i3 := BucketIndex(at(90), w)
	if i1 != i2 {
		t.Fatalf("60s and 89s must share a bucket: %d %d", i1, i2)
	}
	if i3 != i1+1 {
		t.Fatalf("90s must be next bucket: got %d want %d", i3, i1+1)
	}
	if BucketStart(i1, w) != at(60) {
		t.Fatalf("bucket start round-trip mismatch")
	}
}

func TestAddAndEvaluate(t *testing.T) {
	w := NewWindow("c", "z", 30*time.Second, 3, 1, 1)
	scores := map[string]float64{"length": 1.5, "entropy": 1.0}
	if !w.Add(at(0), scores, map[string]float64{"length": 1, "entropy": 1}) {
		t.Fatal("first add accepted")
	}
	if !w.Add(at(30), scores, map[string]float64{"length": 1, "entropy": 1}) {
		t.Fatal("second add accepted")
	}
	ev := w.Evaluate(2.0)
	// depth 3 window indexes 0,1,2; two anomalous, one empty.
	if ev.Sustained != 2 {
		t.Fatalf("sustained run = %d, want 2", ev.Sustained)
	}
	if got := len(ev.ActiveFeatures); got != 2 {
		t.Fatalf("active features = %v", ev.ActiveFeatures)
	}
	if ev.ActiveFeatures[0] != model.FeatureKey("entropy") {
		t.Fatalf("features must be sorted: %v", ev.ActiveFeatures)
	}
}

func TestLateEventRejectedAndDeterministic(t *testing.T) {
	w := NewWindow("c", "z", 30*time.Second, 3, 1, 1)
	// Seed the high bucket (index 3 at 90s). Ingestion horizon then
	// becomes 3-3+1-1 = 0.
	w.Add(at(0), map[string]float64{"x": 1}, map[string]float64{"x": 1})
	w.Add(at(90), map[string]float64{"x": 1}, map[string]float64{"x": 1})
	// Advance with watermark at 120s (idx 4): Advance floor = 4-3+1-1 = 1,
	// so bucket 0 is evicted deterministically.
	evicted := w.Advance(at(120))
	if len(evicted) != 1 || evicted[0] != 0 {
		t.Fatalf("expected bucket 0 evicted, got %v", evicted)
	}
	// Bucket index 1 (30s) is exactly on the late-tolerance floor and
	// must still be accepted.
	if !w.Add(at(30), map[string]float64{"x": 1}, map[string]float64{"x": 1}) {
		t.Fatal("event exactly on late-tolerance floor must be accepted")
	}
	// Bucket index -1 is behind the ingestion horizon (floor==0) and is
	// rejected, even though it was never explicitly evicted by Advance.
	if w.Add(at(-30), map[string]float64{"x": 1}, map[string]float64{"x": 1}) {
		t.Fatal("event behind ingestion horizon must be rejected")
	}
}

func TestAdvanceIdempotentAndRepeatable(t *testing.T) {
	w1 := NewWindow("c", "z", 30*time.Second, 3, 1, 1)
	w2 := NewWindow("c", "z", 30*time.Second, 3, 1, 1)
	stream := []int64{0, 35, 61, 90, 125, 31, 150, 62} // includes late/early
	for _, s := range stream {
		sc := map[string]float64{"x": 1}
		w1.Add(at(s), sc, map[string]float64{"x": 1})
		w2.Add(at(s), sc, map[string]float64{"x": 1})
	}
	// Same watermarks in the same order must yield identical retained sets.
	for _, wm := range []int64{120, 180, 300} {
		a := w1.Advance(at(wm))
		b := w2.Advance(at(wm))
		if len(a) != len(b) {
			t.Fatalf("eviction mismatch at %d", wm)
		}
	}
	e1 := w1.Evaluate(0.5)
	e2 := w2.Evaluate(0.5)
	if e1.Score != e2.Score || e1.Sustained != e2.Sustained {
		t.Fatalf("determinism broken: %+v vs %+v", e1, e2)
	}
	// Advancing again changes nothing.
	w1.Advance(at(300))
	e3 := w1.Evaluate(0.5)
	if e3.Score != e1.Score || e3.Sustained != e1.Sustained {
		t.Fatal("repeated advance must be idempotent")
	}
}

func TestOutOfOrderDoesNotCorrupt(t *testing.T) {
	w := NewWindow("c", "z", 10*time.Second, 4, 2, 1)
	// Insert buckets out of order; all within the late-tolerance horizon.
	for _, s := range []int64{30, 0, 20, 10} {
		if !w.Add(at(s), map[string]float64{"x": 1}, map[string]float64{"x": 1}) {
			t.Fatalf("add at %d rejected unexpectedly", s)
		}
	}
	if len(w.Buckets()) != 4 {
		t.Fatalf("expected 4 buckets, got %d", len(w.Buckets()))
	}
	if w.LowestIndex() != BucketIndex(at(0), 10*time.Second) ||
		w.HighestIndex() != BucketIndex(at(30), 10*time.Second) {
		t.Fatal("lowest/highest incorrect after out-of-order adds")
	}
	// A bucket too far behind the highest observed is rejected.
	if w.Add(at(-30), map[string]float64{"x": 1}, map[string]float64{"x": 1}) {
		t.Fatal("event beyond late-tolerance horizon must be rejected")
	}
}

func TestEmptyBucketsBreakSustainedRun(t *testing.T) {
	w := NewWindow("c", "z", 10*time.Second, 6, 0, 1)
	for _, s := range []int64{0, 10, 30, 40} { // gap at bucket 20
		w.Add(at(s), map[string]float64{"x": 3}, map[string]float64{"x": 1})
	}
	ev := w.Evaluate(2.0)
	if ev.Sustained != 2 {
		t.Fatalf("longest run across a gap must be 2, got %d", ev.Sustained)
	}
}

func TestLoadBucketsRoundTrip(t *testing.T) {
	w := NewWindow("c", "z", 10*time.Second, 4, 1, 7)
	w.Add(at(0), map[string]float64{"x": 2}, map[string]float64{"x": 1})
	w.Add(at(10), map[string]float64{"x": 3}, map[string]float64{"x": 1})
	got := w.Buckets()

	w2 := NewWindow("c", "z", 10*time.Second, 4, 1, 7)
	w2.LoadBuckets(got)
	if w2.LowestIndex() != w.LowestIndex() || w2.HighestIndex() != w.HighestIndex() {
		t.Fatal("indexes not restored")
	}
	if len(w2.Buckets()) != len(got) {
		t.Fatal("buckets not restored")
	}
}
