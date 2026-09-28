package features

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0).UTC()

func TestExtractNameStructural(t *testing.T) {
	long := "abcdefghijklmnopqrstuvwxyz0123456789abcd.tun.example.com."
	f := ExtractName(long)
	if f.HasLongLabel != true {
		t.Fatalf("expected long label flag, longest=%d", f.LongestLabel)
	}
	if f.TotalLength != len(long)-1 { // trailing dot stripped
		t.Fatalf("total length = %d", f.TotalLength)
	}
	if f.LabelCount != 4 {
		t.Fatalf("labels = %d", f.LabelCount)
	}
	if f.Entropy <= 0 || f.Entropy > 1 {
		t.Fatalf("normalized entropy out of range: %f", f.Entropy)
	}
	if f.DigitRatio <= 0 {
		t.Fatal("digit ratio should be positive for alnum label")
	}

	short := ExtractName("a.com")
	if short.HasLongLabel {
		t.Fatal("a.com must not be a long label")
	}
}

func TestShannonEntropyKnown(t *testing.T) {
	// "aaaa" has zero entropy.
	if n, bits := ShannonsEntropy("aaaa"); bits != 0 || n != 0 {
		t.Fatalf("uniform string entropy must be 0, got %f/%f", n, bits)
	}
	// "ab" two equiprobable symbols -> 1 bit, normalized 1.
	n, bits := ShannonsEntropy("ab")
	if math.Abs(bits-1) > 1e-9 || math.Abs(n-1) > 1e-9 {
		t.Fatalf("ab entropy = %f bits / %f norm, want 1/1", bits, n)
	}
}

func TestStatsWelford(t *testing.T) {
	s := NewStats()
	for _, v := range []float64{2, 4, 4, 4, 5, 5, 7, 9} {
		s.Add(v, t0)
	}
	if math.Abs(s.Mean-5) > 1e-9 {
		t.Fatalf("mean = %f, want 5", s.Mean)
	}
	sd := s.StdDev(0)
	// Sample standard deviation (n-1 denominator): variance 32/7.
	if math.Abs(sd-math.Sqrt(32.0/7.0)) > 1e-9 {
		t.Fatalf("sd = %f, want %f", sd, math.Sqrt(32.0/7.0))
	}
	if s.StdDev(10) < 10 {
		t.Fatal("stddev floor must apply")
	}
	if s.Min != 2 || s.Max != 9 {
		t.Fatalf("min/max wrong: %f/%f", s.Min, s.Max)
	}
}

func TestStatsDecayReducesWeight(t *testing.T) {
	s := NewStats()
	for i := 0; i < 100; i++ {
		s.Add(10, t0)
	}
	before := s.Count
	s.ApplyDecay(0.5)
	if s.Count >= before {
		t.Fatal("decay must reduce effective count")
	}
	if math.Abs(s.Mean-10) > 1e-9 {
		t.Fatal("decay must preserve the mean")
	}
}

func TestRateTrackerOrder(t *testing.T) {
	r := NewRateTracker()
	r.Observe(t0)
	if !r.Observe(t0.Add(time.Second)) {
		t.Fatal("later timestamp must advance")
	}
	if got := r.Observe(t0.Add(500 * time.Millisecond)); got {
		t.Fatal("out-of-order timestamp must be ignored")
	}
	if r.MeanIntervalMS() != 1000 {
		t.Fatalf("interval must remain 1000ms, got %f", r.MeanIntervalMS())
	}
	if r.RatePerSecond() <= 0 {
		t.Fatal("rate must be positive after two arrivals")
	}
}

func TestRateTrackerReset(t *testing.T) {
	r := NewRateTracker()
	r.Observe(t0)
	r.Observe(t0.Add(time.Second))
	r.Reset(t0.Add(2 * time.Second))
	if r.MeanIntervalMS() != 0 {
		t.Fatal("reset must clear intervals")
	}
}
