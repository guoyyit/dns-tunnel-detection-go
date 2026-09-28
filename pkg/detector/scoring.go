package detector

import (
	"math"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/baseline"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/config"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/features"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

// Feature name constants used in scores and weights.
const (
	featLength   = "length"
	featEntropy  = "entropy"
	featDigit    = "digit"
	featRate     = "rate"
	featInterval = "interval"
	featAnswer   = "answer"
	featNXDomain = "nxdomain"

	// FeatureTunnel is the single composite alert identity. Alerts are
	// de-duplicated per (client, zone, FeatureTunnel); a genuinely new
	// tunnel zone or a severity change yields a new distinguishable
	// alert.
	FeatureTunnel model.FeatureKey = "tunnel"
)

const (
	zCap = 4.0
	// smallAnswerBytes is the answer size below which a long-name query
	// looks like a tunnel control/heartbeat.
	smallAnswerBytes = 64
	// longLabelFloor is the label length at which a single label begins
	// to look payload-carrying.
	longLabelFloor = 25.0
	// minDistinctFeatures is how many independently-sustained features
	// must be present before a tunnel alert is allowed. This is the core
	// anti-false-positive gate: no single feature can raise an alert.
	minDistinctFeatures = 2
	// featureGate is the average raw strength a feature must sustain
	// across the window to count as a distinct gating feature.
	featureGate = 0.5
	// structuralGate is the raw strength at which a name-shape feature
	// (label length/entropy/digit ratio) counts as payload anomaly.
	structuralGate = 0.5
)

// labelLength scores a single label that is long enough to carry a
// chunk of encoded payload. It ramps from 0 at longLabelFloor to 1 one
// "floor length" beyond it.
func labelLength(labelLen, floor float64) float64 {
	if labelLen < floor {
		return 0
	}
	return math.Min(1, (labelLen-floor)/floor)
}

// absEntropyBand scores entropy that sits in the encoder-typical band.
func absEntropyBand(entropy, lo, hi float64) float64 {
	if entropy < lo || entropy > hi {
		return 0
	}
	return math.Min(1, (entropy-lo)/math.Max(hi-lo, 1e-6))
}

// absDigit scores a high digit fraction (base32/hex payloads).
func absDigit(ratio, floor float64) float64 {
	if ratio < floor {
		return 0
	}
	return math.Min(1, (ratio-floor)/(1-floor))
}

// zAbove returns a normalized [0,1] z-score for "higher is suspicious",
// gated by an absolute floor.
func zAbove(v, mean, sd, floor float64) float64 {
	if v < floor || v <= mean {
		return 0
	}
	return math.Min((v-mean)/sd, zCap) / zCap
}

// zBelow returns a normalized z-score for "lower is suspicious".
func zBelow(v, mean, sd, ceil float64) float64 {
	if v > ceil || v <= 0 || v >= mean {
		return 0
	}
	return math.Min((mean-v)/sd, zCap) / zCap
}

// signal combines an absolute heuristic signal with a relative
// (baseline-deviation) signal by taking the stronger of the two. This
// catches tunnels that are persistently unlike normal traffic even when
// deviation from the series mean is small (a constant anomaly).
func signal(abs, z float64) float64 {
	return math.Max(abs, z)
}

// scoreEvent combines multiple features. It returns:
//   - weighted: per-feature strength in [0,weight] for the aggregate
//     window score / severity;
//   - raw: per-feature unweighted strength in [0,1] for the
//     multi-feature persistence gate.
//
// Features that do not fire are omitted. Detection never depends on a
// single feature: length, entropy, digit ratio, rate, inter-arrival
// interval and response characteristics (tiny answers / NXDOMAIN) each
// contribute independently. Structural absolute signals are recorded
// even while the profile warms up, but the window-level sustained-run
// and multi-feature gates mean a single odd query can never alert.
func scoreEvent(o baseline.Observation, p *baseline.NameProfile, f features.NameFeatures, snap *config.Snapshot) (weighted, raw map[string]float64) {
	cfg := snap.Raw()
	th := cfg.Thresholds
	weighted = make(map[string]float64)
	raw = make(map[string]float64)

	warm := p != nil && p.Samples >= th.MinBaselineSamples

	add := func(name string, s float64) {
		if s <= 0 {
			return
		}
		if s > 1 {
			s = 1
		}
		if s > raw[name] {
			raw[name] = s
		}
	}

	// Structural signals are coupled to a genuinely long label. Shannon
	// entropy is meaningless on short labels ("example" is only 7 mostly
	// distinct characters yet normalizes to ~0.88), so entropy and digit
	// ratio only count once a label is long enough to carry an encoded
	// chunk. This makes "long + high-entropy (+ digit-rich)" a joint
	// payload signature instead of three independent coincidences.
	longEnough := o.LongestLabel >= longLabelFloor
	lenSig := labelLength(o.LongestLabel, longLabelFloor)
	add(featLength, lenSig)
	if longEnough {
		add(featEntropy, absEntropyBand(o.LabelEntropy, th.MinEntropy, th.MaxEntropy))
		add(featDigit, absDigit(o.LabelDigit, 0.15))
	}
	if o.NameLength >= th.MinNameLength {
		if o.NXDomain >= 1 {
			add(featNXDomain, 1)
		}
		if o.AnswerBytes > 0 && o.AnswerBytes < smallAnswerBytes {
			add(featAnswer, 1-o.AnswerBytes/smallAnswerBytes)
		}
	}

	if warm {
		if longEnough {
			add(featLength, signal(lenSig,
				zAbove(o.LongestLabel, p.Length.Mean, p.Length.StdDev(1), longLabelFloor)))
			add(featEntropy, signal(absEntropyBand(o.LabelEntropy, th.MinEntropy, th.MaxEntropy),
				zAbove(o.LabelEntropy, p.Entropy.Mean, p.Entropy.StdDev(0.05), th.MinEntropy)))
			add(featDigit, signal(absDigit(o.LabelDigit, 0.15),
				zAbove(o.LabelDigit, p.Digit.Mean, p.Digit.StdDev(0.02), 0.15)))
		}
	}

	// Behavioral features (high frequency, steady short intervals) can
	// only weight an alert when a long payload-carrying label is present.
	// A busy-but-normal service (short, human-readable names) must never
	// alert on rate alone; this is the main false-positive guard for
	// batch jobs.
	structural := raw[featLength] >= structuralGate
	if structural && warm {
		ratePerMin := o.RatePerSec * 60
		if ratePerMin >= th.MinRatePerMinute {
			meanRate := meanRatePerMin(p)
			var rz float64
			if meanRate > 0 {
				rz = math.Min((ratePerMin-meanRate)/math.Max(meanRate*0.25, 1), zCap) / zCap
			}
			rabs := math.Min((ratePerMin-th.MinRatePerMinute)/th.MinRatePerMinute, 1)
			add(featRate, math.Max(rz, rabs))
		}

		if o.IntervalMS > 0 {
			iz := zBelow(o.IntervalMS, p.Interval.Mean, p.Interval.StdDev(50), th.MaxMeanIntervalMS)
			iabs := 0.0
			if o.IntervalMS <= th.MaxMeanIntervalMS {
				iabs = 1 - o.IntervalMS/th.MaxMeanIntervalMS
			}
			add(featInterval, math.Max(iz, iabs))
		}
	}

	for name, s := range raw {
		if w := cfg.FeatureWeights[name]; w > 0 {
			weighted[name] = s * w
		}
	}
	return weighted, raw
}

// meanRatePerMin derives the baseline mean rate from interval stats.
func meanRatePerMin(p *baseline.NameProfile) float64 {
	if p.Interval.Count == 0 || p.Interval.Mean <= 0 {
		return 0
	}
	return 60000.0 / p.Interval.Mean
}

// severity maps a window score to a severity using config thresholds.
func severity(score float64, th config.Thresholds) model.Severity {
	switch {
	case score >= th.CriticalScore:
		return model.SeverityCritical
	case score >= th.HighScore:
		return model.SeverityHigh
	case score >= th.MinSuspicionScore:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}
