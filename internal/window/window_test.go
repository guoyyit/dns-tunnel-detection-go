package window

import (
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
)

func testCfg() config.WindowConfig {
	return config.WindowConfig{
		Size:            10 * time.Minute,
		Slide:           time.Minute,
		FireScore:       6,
		FireBuckets:     3,
		MaxSuspectScore: 8,
		LatenessGrace:   2 * time.Minute,
	}
}

func TestSingleAnomalyDoesNotFire(t *testing.T) {
	w := New(testCfg())
	ts := time.Unix(1000, 0)
	w.Add("c1", "evil.com", ts, 5, []string{"entropy"}, "x.evil.com")
	ds := w.Evaluate(ts)
	if len(ds) != 1 || ds[0].Fire {
		t.Fatalf("isolated anomaly must not fire: %+v", ds)
	}
}

func TestSustainedFiresAndDeterministic(t *testing.T) {
	run := func() bool {
		w := New(testCfg())
		t0 := time.Unix(1000, 0)
		for i := 0; i < 5; i++ {
			ts := t0.Add(time.Duration(i) * time.Minute)
			w.Add("c1", "evil.com", ts, 2, []string{"entropy", "length"}, "x.evil.com")
		}
		ds := w.Evaluate(t0.Add(5 * time.Minute))
		return len(ds) == 1 && ds[0].Fire && ds[0].Score == 10 && ds[0].Active == 5
	}
	if !run() || !run() {
		t.Fatal("sustained evidence must fire deterministically")
	}
}

func TestOutOfOrderLateAcceptanceAndDrop(t *testing.T) {
	w := New(testCfg())
	t0 := time.Unix(10000, 0)
	w.Add("c1", "evil.com", t0.Add(15*time.Minute), 2, nil, "")
	// within size+grace (12m): 15m-12m = 3m -> ts=4m accepted, ts=2m dropped
	if !w.Add("c1", "evil.com", t0.Add(4*time.Minute), 2, nil, "") {
		t.Error("event within grace should be accepted")
	}
	if w.Add("c1", "evil.com", t0.Add(2*time.Minute), 2, nil, "") {
		t.Error("event beyond grace should be dropped")
	}
}

func TestAdvanceEvicts(t *testing.T) {
	w := New(testCfg())
	t0 := time.Unix(10000, 0)
	w.Add("c1", "evil.com", t0, 2, nil, "")
	w.Advance(t0.Add(20 * time.Minute))
	if len(w.Evaluate(t0.Add(20*time.Minute))) != 0 {
		t.Fatal("expired state should have been evicted")
	}
}

func TestExportRestoreRoundTrip(t *testing.T) {
	w := New(testCfg())
	t0 := time.Unix(10000, 0)
	for i := 0; i < 4; i++ {
		w.Add("c1", "evil.com", t0.Add(time.Duration(i)*time.Minute), 2, []string{"e"}, "s")
	}
	snap := w.Export()
	w2 := New(testCfg())
	w2.Restore(snap)
	ds := w2.Evaluate(t0.Add(4 * time.Minute))
	if len(ds) != 1 || !ds[0].Fire || ds[0].Score != 8 {
		t.Fatalf("restored window mismatch: %+v", ds)
	}
}
