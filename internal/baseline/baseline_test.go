package baseline

import (
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

func TestObserveAndTrusted(t *testing.T) {
	cfg := config.Default().Baseline
	cfg.MinSamples = 3
	tr := NewTracker(cfg, time.Second)
	ts := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		ev := &model.Event{TS: ts.Add(time.Duration(i) * time.Second), ClientIP: "c1", QName: "a.b.example"}
		f := model.Feature{NameLen: 10 + i, Entropy: 2.5, DigitRatio: 0.1, LongestLabel: 7}
		tr.Observe(ev, f, ev.TS)
	}
	c := tr.Client("c1")
	if c == nil || c.Count != 5 {
		t.Fatalf("client baseline wrong: %+v", c)
	}
	if !tr.IsTrusted("c1") {
		t.Error("expected trusted baseline")
	}
	if c.Intervals.N != 4 {
		t.Errorf("intervals observed=%d want 4", c.Intervals.N)
	}
	if c.NameLen.Mean < 10 || c.NameLen.Mean > 14 {
		t.Errorf("name len mean drifted: %v", c.NameLen.Mean)
	}
	if tr.IsTrusted("ghost") {
		t.Error("unknown client must not be trusted")
	}
}

func TestEvictIdleAndCap(t *testing.T) {
	cfg := config.Default().Baseline
	cfg.MaxBaselineKeys = 2
	tr := NewTracker(cfg, time.Second)
	for i, ip := range []string{"a", "b", "c"} {
		ev := &model.Event{ClientIP: ip, QName: ip + ".x"}
		ts := time.Unix(int64(i), 0)
		tr.Observe(ev, model.Feature{NameLen: 3}, ts)
	}
	tr.Evict(time.Time{})
	if len(tr.clients) != 2 {
		t.Fatalf("cap enforcement clients=%d want 2", len(tr.clients))
	}
	// idle eviction
	tr.Evict(time.Unix(10, 0))
	if len(tr.clients) != 0 || len(tr.names) != 0 {
		t.Fatalf("idle eviction failed: %d %d", len(tr.clients), len(tr.names))
	}
}
