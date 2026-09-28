// Package config defines detection configuration, whitelist/exemption
// rules and immutable configuration snapshots.
package config

import (
	"regexp"
	"strings"
	"sync/atomic"
)

// Thresholds groups per-feature detection thresholds.
type Thresholds struct {
	// MinBaselineSamples is how many observations a profile needs
	// before anomaly scoring is allowed.
	MinBaselineSamples int64
	// MinNameLength is the full-name length above which length is
	// considered at all anomalous (relative to baseline too).
	MinNameLength float64
	// MinEntropy / MaxEntropy bracket the entropy range typical of
	// encoded tunnel labels (high randomness). Base32/Base64 payloads
	// usually land inside this band.
	MinEntropy float64
	MaxEntropy float64
	// MinRatePerMinute is the minimum query frequency (per minute) for a
	// (client,name) series before rate can contribute suspicion.
	MinRatePerMinute float64
	// MaxMeanIntervalMS: mean inter-arrival below this (bursty, steady
	// beaconing) can contribute suspicion.
	MaxMeanIntervalMS float64
	// MinSuspicionScore is the score a bucket needs to count as
	// anomalous.
	MinSuspicionScore float64
	// MinSustainedBuckets is the number of anomalous buckets that must
	// be present in the window before an alert can fire.
	MinSustainedBuckets int
	// HighScore / CriticalScore map the window score to severity.
	HighScore     float64
	CriticalScore float64
	// DriftTauSec is the exponential decay time constant for baseline
	// drift adaptation.
	DriftTauSec float64
}

// Rule is a whitelist or exemption rule. Zero-valued optional fields
// act as wildcards.
type Rule struct {
	// Name is an optional human-readable description.
	Name string
	// ClientIP, when set, restricts the rule to one client.
	ClientIP string
	// NameSuffix matches if the query name equals or is a subdomain of
	// the suffix (e.g. "example.com" matches "a.b.example.com").
	NameSuffix string
	// NameRegexp, when set, must match the query name.
	NameRegexp string
	// Heartbeat marks known heartbeat/beacon domains. It is purely
	// informational on the rule; matching rules act like exemptions.
	Heartbeat bool
}

// Config is the mutable, user-facing configuration.
type Config struct {
	// WindowSizeSec is the sliding window horizon.
	WindowSizeSec int
	// BucketWidthSec is the fixed bucket width; depth is derived as
	// WindowSizeSec/BucketWidthSec.
	BucketWidthSec int
	// LateToleranceSec: events more than this many seconds behind the
	// watermark are rejected deterministically.
	LateToleranceSec int
	// CooldownSec is the per-(client,feature) alert cooldown.
	CooldownSec int

	// MaxClients bounds the number of tracked clients; MaxNames bounds
	// per-client tracked names. Overflow evicts least-recently-updated
	// entries.
	MaxClients int
	MaxNames   int

	// FeatureWeights maps feature names to their weight in the combined
	// suspicion score. Unknown features are ignored; zero weight
	// disables a feature.
	FeatureWeights map[string]float64
	Thresholds     Thresholds

	Whitelist  []Rule
	Exemptions []Rule

	// PersistPath is the snapshot file; empty disables persistence.
	PersistPath string
	// PersistPeriodMS is the background snapshot interval.
	PersistPeriodMS int
}

// Default returns a working configuration with conservative defaults.
func Default() *Config {
	return &Config{
		WindowSizeSec:    300,
		BucketWidthSec:   30,
		LateToleranceSec: 90,
		CooldownSec:      600,

		MaxClients: 10000,
		MaxNames:   10000,

		FeatureWeights: map[string]float64{
			"length":   1.0,
			"entropy":  1.2,
			"digit":    0.8,
			"rate":     1.0,
			"interval": 0.8,
			"answer":   0.6,
			"nxdomain": 0.6,
		},
		Thresholds: Thresholds{
			MinBaselineSamples:  20,
			MinNameLength:       40,
			MinEntropy:          0.8,
			MaxEntropy:          1.0,
			MinRatePerMinute:    30,
			MaxMeanIntervalMS:   2500,
			MinSuspicionScore:   2.0,
			MinSustainedBuckets: 4,
			HighScore:           3.5,
			CriticalScore:       5.0,
			DriftTauSec:         1800,
		},

		PersistPath:     "",
		PersistPeriodMS: 2000,
	}
}

// compiledRule is a Rule with its regexp compiled.
type compiledRule struct {
	rule Rule
	re   *regexp.Regexp // nil when unset
}

func (r compiledRule) matches(clientIP, name string) bool {
	if r.rule.ClientIP != "" && r.rule.ClientIP != clientIP {
		return false
	}
	if r.rule.NameSuffix != "" && !hasSuffixDomain(name, r.rule.NameSuffix) {
		return false
	}
	if r.re != nil && !r.re.MatchString(name) {
		return false
	}
	return true
}

// hasSuffixDomain reports whether name equals suffix or is a subdomain
// of suffix. Both are compared case-insensitively without trailing dots.
func hasSuffixDomain(name, suffix string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	if name == suffix {
		return true
	}
	return strings.HasSuffix(name, "."+suffix)
}

// Snapshot is an immutable view of a Config. Evaluations in progress
// keep holding the snapshot they started with, so a config replacement
// never mixes old and new rules inside one window evaluation.
type Snapshot struct {
	cfg        *Config
	gen        int64
	whitelist  []compiledRule
	exemptions []compiledRule
}

// Snapshot builds an immutable snapshot; an invalid regexp yields an
// error so callers never silently run a broken rule set. The snapshot
// deep-copies the config, so later mutation of the source Config cannot
// affect an evaluation already holding the snapshot.
func (c *Config) Snapshot(gen int64) (*Snapshot, error) {
	cp := *c
	cp.FeatureWeights = make(map[string]float64, len(c.FeatureWeights))
	for k, v := range c.FeatureWeights {
		cp.FeatureWeights[k] = v
	}
	cp.Whitelist = append([]Rule(nil), c.Whitelist...)
	cp.Exemptions = append([]Rule(nil), c.Exemptions...)
	s := &Snapshot{cfg: &cp, gen: gen}
	compile := func(rules []Rule) ([]compiledRule, error) {
		out := make([]compiledRule, 0, len(rules))
		for _, r := range rules {
			cr := compiledRule{rule: r}
			if r.NameRegexp != "" {
				re, err := regexp.Compile(r.NameRegexp)
				if err != nil {
					return nil, err
				}
				cr.re = re
			}
			out = append(out, cr)
		}
		return out, nil
	}
	var err error
	if s.whitelist, err = compile(c.Whitelist); err != nil {
		return nil, err
	}
	if s.exemptions, err = compile(c.Exemptions); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Snapshot) Generation() int64 { return s.gen }

func (s *Snapshot) Raw() *Config { return s.cfg }

func (s *Snapshot) matchAny(rules []compiledRule, clientIP, name string) bool {
	for _, r := range rules {
		if r.matches(clientIP, name) {
			return true
		}
	}
	return false
}

// IsWhitelisted reports whether the series is fully trusted: whitelisted
// traffic is neither baselined nor scored.
func (s *Snapshot) IsWhitelisted(clientIP, name string) bool {
	return s.matchAny(s.whitelist, clientIP, name)
}

// IsExempt reports whether the series still feeds the baseline but must
// never raise alerts (heartbeat domains, approved batch jobs).
func (s *Snapshot) IsExempt(clientIP, name string) bool {
	return s.matchAny(s.exemptions, clientIP, name)
}

// Store atomically serves configuration snapshots.
type Store struct {
	cur atomic.Pointer[Snapshot]
	gen atomic.Int64
}

// NewStore creates a store from the default generation (1).
func NewStore(c *Config) (*Store, error) {
	st := &Store{}
	st.gen.Store(1)
	s, err := c.Snapshot(1)
	if err != nil {
		return nil, err
	}
	st.cur.Store(s)
	return st, nil
}

func (st *Store) Current() *Snapshot { return st.cur.Load() }

// Replace atomically installs a new configuration snapshot with a fresh
// generation number. Old snapshots remain valid for any evaluation that
// already holds them.
func (st *Store) Replace(c *Config) error {
	gen := st.gen.Add(1)
	s, err := c.Snapshot(gen)
	if err != nil {
		return err
	}
	st.cur.Store(s)
	return nil
}
