package baseline

import (
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0).UTC()

func obs(at time.Time, length, entropy, rate, interval float64) Observation {
	return Observation{At: at, LongestLabel: length, LabelEntropy: entropy,
		RatePerSec: rate, IntervalMS: interval}
}

func TestPerClientAndNameIsolation(t *testing.T) {
	r := NewRegistry(10, 10, 1000)
	r.Profile("a", "x.com", t0).Observe(obs(t0, 10, 0.1, 1, 1000))
	r.Profile("a", "x.com", t0).Observe(obs(t0, 12, 0.1, 1, 1000))
	r.Profile("b", "x.com", t0).Observe(obs(t0, 90, 0.9, 10, 100))

	pa := r.Profile("a", "x.com", t0)
	pb := r.Profile("b", "x.com", t0)
	if pa.Length.Mean == pb.Length.Mean {
		t.Fatal("clients must have independent baselines")
	}
	if pa.Length.Mean < 10 || pa.Length.Mean > 12 {
		t.Fatalf("client a mean = %f", pa.Length.Mean)
	}
}

func TestDriftDecayAdapts(t *testing.T) {
	b := NewClientBaseline("a", t0)
	b.tauSec = 100
	// Long period of short names.
	for i := 0; i < 100; i++ {
		b.Observe("x.com", obs(t0.Add(time.Duration(i)*time.Second), 10, 0.1, 1, 1000))
	}
	p, _ := b.Get("x.com")
	if p.Length.Mean > 11 {
		t.Fatalf("pre-drift mean = %f", p.Length.Mean)
	}
	// After a long idle gap (>> tau) old samples decay heavily; new
	// longer names move the distribution quickly (baseline drift).
	later := t0.Add(1000 * time.Second)
	for i := 0; i < 20; i++ {
		b.Observe("x.com", obs(later.Add(time.Duration(i)*time.Second), 60, 0.1, 1, 1000))
	}
	p, _ = b.Get("x.com")
	if p.Length.Mean < 30 {
		t.Fatalf("baseline did not adapt to drift, mean = %f", p.Length.Mean)
	}
}

func TestMaxNamesAndClientsEviction(t *testing.T) {
	r := NewRegistry(2, 2, 1000)
	r.Profile("c1", "a.com", t0).Observe(obs(t0, 1, 0, 0, 0))
	time.Sleep(2 * time.Millisecond)
	r.Profile("c1", "b.com", t0.Add(time.Millisecond)).Observe(obs(t0, 0, 0, 0, 0))
	time.Sleep(2 * time.Millisecond)
	r.Profile("c1", "c.com", t0.Add(2*time.Millisecond)).Observe(obs(t0, 0, 0, 0, 0))
	if r.Client("c1", t0).Names() != 2 {
		t.Fatalf("per-client names must be bounded to 2, got %d", r.Client("c1", t0).Names())
	}

	r.Client("c2", t0)
	r.Client("c3", t0)
	if r.ClientCount() != 2 {
		t.Fatalf("clients must be bounded to 2, got %d", r.ClientCount())
	}
}

func TestPruneRemovesStale(t *testing.T) {
	r := NewRegistry(100, 100, 1000)
	r.Profile("c1", "a.com", t0)
	r.Profile("c2", "a.com", t0.Add(10*time.Second))
	removed := r.Prune(t0.Add(5 * time.Second))
	if removed != 1 || r.ClientCount() != 1 {
		t.Fatalf("prune removed %d, clients %d", removed, r.ClientCount())
	}
}

func TestSetTau(t *testing.T) {
	r := NewRegistry(10, 10, 1)
	r.Client("c", t0)
	r.SetTau(999)
	if r.tauSec != 999 {
		t.Fatal("registry tau not updated")
	}
	if got := r.Client("c", t0).tauSec; got != 999 {
		t.Fatalf("existing client tau = %v", got)
	}
}
