// Package features computes per-query name features and maintains
// streaming statistics used by baselines and scoring.
package features

import (
	"math"
	"strings"
	"time"
)

// LongLabelThreshold is the label length at or above which a label is
// treated as a long (potentially payload-carrying) label.
const LongLabelThreshold = 30

// NameFeatures are features derived purely from a query name.
type NameFeatures struct {
	Name         string
	LabelCount   int
	TotalLength  int
	LongestLabel int
	Entropy      float64
	DigitRatio   float64
	// LongestLabelEntropy / LongestLabelDigit characterize only the
	// longest label (where an encoded payload sits), ignoring the stable
	// parent zone. Human-readable labels keep vowel/consonant structure
	// and low entropy; base32/hex labels are near-uniform.
	LongestLabelEntropy float64
	LongestLabelDigit   float64
	ConsonantRatio      float64
	HasLongLabel        bool
}

// ExtractName derives structural and character features from a query
// name. The name is lowercased and stripped of a trailing dot.
func ExtractName(name string) NameFeatures {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	f := NameFeatures{Name: n, TotalLength: len(n)}

	labels := strings.Split(n, ".")
	longest := ""
	for _, l := range labels {
		if l == "" {
			continue
		}
		f.LabelCount++
		if len(l) > f.LongestLabel {
			f.LongestLabel = len(l)
			longest = l
		}
	}
	f.HasLongLabel = f.LongestLabel >= LongLabelThreshold

	if len(n) > 0 {
		norm, bits := ShannonsEntropy(n)
		f.Entropy = norm
		_ = bits
		var digits, consonants, letters int
		for _, r := range n {
			switch {
			case r >= '0' && r <= '9':
				digits++
			case r >= 'a' && r <= 'z':
				letters++
				switch r {
				case 'a', 'e', 'i', 'o', 'u', 'y':
				default:
					consonants++
				}
			}
		}
		f.DigitRatio = float64(digits) / float64(len(n))
		if letters > 0 {
			f.ConsonantRatio = float64(consonants) / float64(letters)
		}
	}
	// Characterize the longest label alone (the payload carrier).
	if longest != "" {
		f.LongestLabelEntropy, _ = ShannonsEntropy(longest)
		d := 0
		for _, r := range longest {
			if r >= '0' && r <= '9' {
				d++
			}
		}
		f.LongestLabelDigit = float64(d) / float64(len(longest))
	}
	return f
}

// ShannonsEntropy returns the per-character Shannon entropy of s, both
// normalized to [0,1] (divided by the maximum entropy for the observed
// alphabet) and in raw bits.
func ShannonsEntropy(s string) (normalized, bits float64) {
	if len(s) == 0 {
		return 0, 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	alphabet := 0
	n := float64(len(s))
	for _, c := range freq {
		if c > 0 {
			alphabet++
			p := float64(c) / n
			bits -= p * math.Log2(p)
		}
	}
	maxBits := math.Log2(float64(alphabet))
	if maxBits > 0 {
		normalized = bits / maxBits
	}
	return normalized, bits
}

// Stats are streaming statistics for one feature series using Welford's
// online algorithm. A single owner goroutine accesses a Stats value;
// methods are not concurrency-safe.
type Stats struct {
	Count    int64
	Mean     float64
	M2       float64
	Min      float64
	Max      float64
	Last     float64
	LastSeen time.Time
}

func NewStats() *Stats {
	return &Stats{}
}

// Add incorporates one sample.
func (s *Stats) Add(v float64, at time.Time) {
	s.Count++
	delta := v - s.Mean
	s.Mean += delta / float64(s.Count)
	s.M2 += delta * (v - s.Mean)
	if s.Count == 1 {
		s.Min, s.Max = v, v
	} else {
		if v < s.Min {
			s.Min = v
		}
		if v > s.Max {
			s.Max = v
		}
	}
	s.Last = v
	s.LastSeen = at
}

// ApplyDecay exponentially discounts older samples. factor in (0,1]
// scales count and M2 while preserving the mean; repeated decay over
// constant time steps yields an exponential moving distribution. This
// is how baselines adapt to drift.
func (s *Stats) ApplyDecay(factor float64) {
	if factor <= 0 || factor >= 1 || s.Count == 0 {
		return
	}
	s.Count = int64(math.Round(float64(s.Count) * factor))
	if s.Count < 1 {
		s.Count = 1
	}
	s.M2 *= factor
}

// StdDev returns the standard deviation floored at floor (so z-scores
// never divide by zero).
func (s *Stats) StdDev(floor float64) float64 {
	if s.Count < 2 {
		return floor
	}
	v := s.M2 / float64(s.Count-1)
	sd := math.Sqrt(v)
	if sd < floor {
		return floor
	}
	return sd
}

// ewmaAlpha is the weight of a new instantaneous sample in the rate EWMA.
const ewmaAlpha = 0.3

// RateTracker estimates event rate (events per second) using an EWMA
// and tracks inter-arrival intervals. Out-of-order timestamps never
// corrupt the state: observations at or before the last-seen timestamp
// are ignored for rate/interval purposes.
type RateTracker struct {
	last     time.Time
	haveLast bool
	rateEWMA float64
	// intervals holds inter-arrival times in milliseconds.
	intervals Stats
}

func NewRateTracker() *RateTracker { return &RateTracker{} }

// Observe records an arrival. Returns true when the observation moved
// the clock forward (false when ignored as out-of-order).
func (r *RateTracker) Observe(at time.Time) bool {
	if r.haveLast && !at.After(r.last) {
		return false
	}
	if r.haveLast {
		gap := at.Sub(r.last)
		if gap > 0 {
			ms := float64(gap) / float64(time.Millisecond)
			r.intervals.Add(ms, at)
			inst := 1000.0 / ms
			if r.rateEWMA == 0 {
				r.rateEWMA = inst
			} else {
				r.rateEWMA = ewmaAlpha*inst + (1-ewmaAlpha)*r.rateEWMA
			}
		}
	}
	r.last = at
	r.haveLast = true
	return true
}

func (r *RateTracker) RatePerSecond() float64 { return r.rateEWMA }

func (r *RateTracker) MeanIntervalMS() float64 {
	if r.intervals.Count == 0 {
		return 0
	}
	return r.intervals.Mean
}

// Reset starts a fresh rate clock while keeping the supplied timestamp
// as the first observation anchor (no interval is recorded).
func (r *RateTracker) Reset(at time.Time) {
	r.last = at
	r.haveLast = true
	r.rateEWMA = 0
	r.intervals = Stats{}
}
