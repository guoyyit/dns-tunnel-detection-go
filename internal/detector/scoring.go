package detector

import (
	"math"
	"strings"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/baseline"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

// scoreResult is the per-event anomaly assessment.
type scoreResult struct {
	score   float64
	reasons []string
	key     string // tunnel feature identifier (registered-ish parent domain)
}

// tunnelKey extracts a stable "tunnel feature" identity from the query
// name: the last two labels (e.g. "evil.io" for "a3f....evil.io"). Events
// on different subdomains of the same tunnel therefore aggregate, while
// genuinely different parent domains alert independently.
func tunnelKey(qname string) string {
	n := strings.ToLower(strings.TrimSuffix(qname, "."))
	parts := strings.Split(n, ".")
	if len(parts) <= 2 {
		return n
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// zStrength returns a bounded positive deviation strength: how many
// standard deviations x lies ABOVE the EWMA mean, minus the configured
// tolerance band. Zero when the baseline is untrusted or within band.
func zStrength(s *baseline.Stats, x, factor, capZ, minSamples float64) float64 {
	if s == nil || float64(s.N) < minSamples {
		return 0
	}
	sd := s.Stddev()
	// relative floor avoids divide-by-zero on perfectly stable metrics
	scale := sd
	if scale < 0.05*math.Abs(s.Mean)+1e-9 {
		scale = 0.05*math.Abs(s.Mean) + 1e-9
	}
	z := (x - s.Mean) / scale
	if z <= factor {
		return 0
	}
	return math.Min(capZ, z-factor)
}

// lowTailStrength detects unusually SMALL values (e.g. short intervals).
func lowTailStrength(s *baseline.Stats, x, factor, capZ, minSamples float64) float64 {
	if s == nil || float64(s.N) < minSamples {
		return 0
	}
	sd := s.Stddev()
	scale := sd
	if scale < 0.05*math.Abs(s.Mean)+1e-6 {
		scale = 0.05*math.Abs(s.Mean) + 1e-6
	}
	z := (s.Mean - x) / scale
	if z <= factor {
		return 0
	}
	return math.Min(capZ, z-factor)
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// score computes multi-feature evidence. It reads baselines but does NOT
// mutate them; the caller observes the event afterwards, so scoring always
// compares against history excluding the current event.
//
// currentBucketHits is the number of events for this qname in the current
// slide bucket including this one; bucketWidth converts to QPS.
func score(
	cfg config.Config,
	tr *baseline.Tracker,
	e *model.Event,
	f model.Feature,
	gapMicros int64,
	currentBucketHits int64,
) scoreResult {
	sc := cfg.Scoring
	bc := cfg.Baseline
	minS := float64(bc.MinSamples)
	factor := bc.DriftZStdFactor
	capZ := bc.DriftCap

	var strength float64
	var reasons []string
	add := func(name string, w, v float64) {
		if v <= 0 {
			return
		}
		strength += w * v
		reasons = append(reasons, name)
	}

	cb := tr.Client(e.ClientIP)
	trusted := tr.IsTrusted(e.ClientIP)

	// --- query name length: absolute threshold OR drift above baseline ---
	var vLen float64
	if f.NameLen > sc.NameLenAbsThreshold {
		vLen = clamp01(float64(f.NameLen-sc.NameLenAbsThreshold) / float64(sc.NameLenAbsThreshold))
	}
	if trusted {
		vLen += zStrength(&cb.NameLen, float64(f.NameLen), factor, capZ, minS)
	}
	add("name_len", sc.WNameLen, math.Min(capZ, vLen))

	// --- Shannon entropy of the name ---
	var vEnt float64
	if f.Entropy > sc.EntropyAbsThreshold {
		vEnt = clamp01((f.Entropy - sc.EntropyAbsThreshold) / sc.EntropyAbsThreshold)
	}
	if trusted {
		vEnt += zStrength(&cb.Entropy, f.Entropy, factor, capZ, minS)
	}
	add("entropy", sc.WEntropy, math.Min(capZ, vEnt))

	// --- digit ratio (encoded payloads are digit/random heavy) ---
	if trusted {
		add("digit_ratio", sc.WDigitRatio, zStrength(&cb.Digit, f.DigitRatio, factor, capZ, minS))
	}

	// --- longest label ---
	longThr := float64(sc.NameLenAbsThreshold) * 0.6
	var vLong float64
	if float64(f.LongestLabel) > longThr {
		vLong = clamp01((float64(f.LongestLabel) - longThr) / longThr)
	}
	if trusted {
		vLong += zStrength(&cb.LongestLbl, float64(f.LongestLabel), factor, capZ, minS)
	}
	add("long_label", sc.WLongLabel, math.Min(capZ, vLong))

	// --- frequency: only high QPS; periodic heartbeat/low-rate never trips ---
	qps := 0.0
	if cfg.Window.Slide > 0 {
		qps = float64(currentBucketHits) / cfg.Window.Slide.Seconds()
	}
	if qps > sc.FreqQPSThreshold && qps > bc.HeartbeatMaxQPS {
		vFreq := clamp01((qps - sc.FreqQPSThreshold) / sc.FreqQPSThreshold)
		if nb := tr.Name(e.QName); nb != nil {
			vFreq += zStrength(&nb.QPS, qps, factor, capZ, minS)
		}
		add("high_frequency", sc.WFrequency, math.Min(capZ, vFreq))
	}

	// --- query interval: unusually short gaps (burst tunneling) ---
	if trusted && gapMicros > 0 {
		add("short_interval", sc.WInterval,
			lowTailStrength(&cb.Intervals, float64(gapMicros), factor, capZ, minS))
	}

	// --- response characteristics: NXDOMAIN-heavy / answer-less traffic ---
	// These are weak signals on their own by design.
	if f.NXDomain {
		vNX := 0.5
		if trusted && cb.NXRate.N > 0 && cb.NXRate.Mean > 0.5 {
			vNX = 1.0
		}
		add("nxdomain", sc.WNXDomain, vNX)
	}
	if f.HasResponse && f.AnsCount == 0 && !f.NXDomain {
		add("no_answer", sc.WNoResponse, 0.5)
	}

	if cfg.Window.MaxSuspectScore > 0 && strength > cfg.Window.MaxSuspectScore {
		strength = cfg.Window.MaxSuspectScore
	}
	return scoreResult{score: strength, reasons: reasons, key: tunnelKey(e.QName)}
}

// hitsInCurrentBucket returns current-bucket hit count (including this
// event) for a qname using the tracker's bucket bookkeeping.
func hitsInCurrentBucket(nb *baseline.NameBase, ts time.Time, width time.Duration) int64 {
	if nb == nil || width <= 0 {
		return 1
	}
	start := nb.BucketStart()
	if start.IsZero() {
		return 1
	}
	if ts.Truncate(width).Equal(start) {
		return nb.BucketHits() + 1
	}
	return 1
}
