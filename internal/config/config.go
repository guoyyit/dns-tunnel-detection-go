// Package config defines detection configuration and immutable
// whitelist/rule snapshots.
package config

import (
	"regexp"
	"time"
)

// Config is the complete detection configuration.
type Config struct {
	Window      WindowConfig      `json:"window"`
	Scoring     ScoringConfig     `json:"scoring"`
	Baseline    BaselineConfig    `json:"baseline"`
	Cooldown    CooldownConfig    `json:"cooldown"`
	Whitelist   WhitelistConfig   `json:"whitelist"`
	Ingest      IngestConfig      `json:"ingest"`
	Persistence PersistenceConfig `json:"persistence"`
}

// WindowConfig controls the sliding accumulation window.
type WindowConfig struct {
	Size            time.Duration `json:"size"`              // total window length
	Slide           time.Duration `json:"slide"`             // bucket width
	FireScore       float64       `json:"fire_score"`        // sustained score threshold
	FireBuckets     int           `json:"fire_buckets"`      // min active buckets inside window
	MaxSuspectScore float64       `json:"max_suspect_score"` // per-event score cap
	LatenessGrace   time.Duration `json:"lateness_grace"`    // late events beyond watermark-grace are dropped
}

// ScoringConfig weights individual anomaly signals. A signal's raw
// contribution is bounded z-score/absolute deviation, multiplied by weight.
type ScoringConfig struct {
	WNameLen    float64 `json:"w_name_len"`
	WEntropy    float64 `json:"w_entropy"`
	WDigitRatio float64 `json:"w_digit_ratio"`
	WFrequency  float64 `json:"w_frequency"`
	WInterval   float64 `json:"w_interval"`
	WNXDomain   float64 `json:"w_nxdomain"`
	WNoResponse float64 `json:"w_no_response"`
	WLongLabel  float64 `json:"w_long_label"`

	NameLenAbsThreshold int     `json:"name_len_abs_threshold"`
	EntropyAbsThreshold float64 `json:"entropy_abs_threshold"`
	FreqQPSThreshold    float64 `json:"freq_qps_threshold"`
}

// BaselineConfig controls the evolving per-client / per-name baselines.
type BaselineConfig struct {
	MinSamples      int     `json:"min_samples"`       // samples before baseline is trusted
	EWMAAlpha       float64 `json:"ewma_alpha"`        // 0..1, higher adapts faster
	DriftZStdFactor float64 `json:"drift_z_factor"`    // anomaly when x > mean + factor*stddev
	DriftCap        float64 `json:"drift_cap"`         // max z contribution per signal
	HeartbeatMaxQPS float64 `json:"heartbeat_max_qps"` // periodic low-rate traffic is benign
	MaxBaselineKeys int     `json:"max_baseline_keys"` // bounded memory
}

// CooldownConfig controls alert deduplication.
type CooldownConfig struct {
	Duration         time.Duration `json:"duration"`
	SeverityEscalate bool          `json:"escalate_on_severity_change"`
	MaxActiveKeys    int           `json:"max_active_keys"`
}

// WhitelistConfig defines exemptions in human-authored form.
type WhitelistConfig struct {
	Suffixes []string `json:"suffixes"` // parent-domain suffix matches
	Regexps  []string `json:"regexps"`  // validated patterns matched against qname
	Clients  []string `json:"clients"`  // exempt client IPs
}

// IngestConfig controls concurrent ingestion and bounded memory.
type IngestConfig struct {
	ShardCount int `json:"shard_count"`
	QueueSize  int `json:"queue_size"`
	MaxTracked int `json:"max_tracked"`
}

// PersistenceConfig controls WAL + snapshot recovery.
type PersistenceConfig struct {
	Dir           string        `json:"dir"`
	SnapshotEvery int           `json:"snapshot_every_events"`
	WALMaxBytes   int64         `json:"wal_max_bytes"`
	FlushInterval time.Duration `json:"flush_interval"`
}

// Default returns a tuned, usable default configuration.
func Default() Config {
	return Config{
		Window: WindowConfig{
			Size:            10 * time.Minute,
			Slide:           30 * time.Second,
			FireScore:       6.0,
			FireBuckets:     6, // e.g. evidence in >=3 of 10 minutes worth... (6 x 30s buckets)
			MaxSuspectScore: 8,
			LatenessGrace:   2 * time.Minute,
		},
		Scoring: ScoringConfig{
			WNameLen:            1.5,
			WEntropy:            1.2,
			WDigitRatio:         1.0,
			WFrequency:          1.5,
			WInterval:           1.0,
			WNXDomain:           1.0,
			WNoResponse:         0.5,
			WLongLabel:          1.0,
			NameLenAbsThreshold: 60,
			EntropyAbsThreshold: 4.2,
			FreqQPSThreshold:    8.0,
		},
		Baseline: BaselineConfig{
			MinSamples:      20,
			EWMAAlpha:       0.1,
			DriftZStdFactor: 2.5,
			DriftCap:        3.0,
			HeartbeatMaxQPS: 0.2,
			MaxBaselineKeys: 100000,
		},
		Cooldown: CooldownConfig{
			Duration:         15 * time.Minute,
			SeverityEscalate: true,
			MaxActiveKeys:    50000,
		},
		Whitelist: WhitelistConfig{},
		Ingest: IngestConfig{
			ShardCount: 16,
			QueueSize:  4096,
			MaxTracked: 200000,
		},
		Persistence: PersistenceConfig{
			SnapshotEvery: 10000,
			WALMaxBytes:   64 << 20,
			FlushInterval: time.Second,
		},
	}
}

// Snapshot is an immutable, compiled generation of rules. A window
// evaluation always references exactly one snapshot generation; config
// updates allocate a new generation and never mutate the old one, so
// in-flight windows never mix old and new rules.
type Snapshot struct {
	Gen      int64
	suffixes []string
	regexps  []*regexp.Regexp
	clients  map[string]struct{}
}

// Compile builds an immutable snapshot. Invalid regexps cause an error.
func (w WhitelistConfig) Compile(gen int64) (*Snapshot, error) {
	snap := &Snapshot{
		Gen:     gen,
		clients: map[string]struct{}{},
	}
	for _, s := range w.Suffixes {
		snap.suffixes = append(snap.suffixes, normalizeSuffix(s))
	}
	for _, pat := range w.Regexps {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		snap.regexps = append(snap.regexps, re)
	}
	for _, c := range w.Clients {
		snap.clients[c] = struct{}{}
	}
	return snap, nil
}

func normalizeSuffix(s string) string {
	out := toLowerASCII(s)
	if len(out) > 0 && out[0] == '.' {
		out = out[1:]
	}
	return out
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// ExemptClient reports whether the client is fully exempt.
func (s *Snapshot) ExemptClient(ip string) bool {
	if s == nil {
		return false
	}
	_, ok := s.clients[ip]
	return ok
}

// ExemptName reports whether the query name matches an exemption rule.
// Suffix matching is label-aware: "example.com" exempts "a.example.com"
// but not "notexample.com".
func (s *Snapshot) ExemptName(qname string) bool {
	if s == nil {
		return false
	}
	n := toLowerASCII(qname)
	for len(n) > 0 && n[len(n)-1] == '.' {
		n = n[:len(n)-1]
	}
	for _, suf := range s.suffixes {
		if n == suf || (len(n) > len(suf) && n[len(n)-len(suf)-1] == '.' && n[len(n)-len(suf):] == suf) {
			return true
		}
	}
	for _, re := range s.regexps {
		if re.MatchString(n) {
			return true
		}
	}
	return false
}
