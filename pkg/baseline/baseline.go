// Package baseline maintains evolvable per-client and per-name baselines.
//
// Baselines use drift-adaptive streaming statistics: old observations
// decay exponentially (tau), so legitimate long-term changes (baseline
// drift, e.g. a new approved batch job or longer names after a client
// upgrade) are absorbed instead of causing persistent false positives.
package baseline

import (
	"math"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/features"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

// Observation is one scored feature vector fed to a baseline.
type Observation struct {
	At time.Time

	NameLength   float64
	LongestLabel float64
	LabelEntropy float64
	LabelDigit   float64
	Entropy      float64
	DigitRatio   float64
	RatePerSec   float64
	IntervalMS   float64
	AnswerBytes  float64
	IPCount      float64
	NXDomain     float64
}

// FromEvent builds an Observation. The rate tracker must already have
// observed the event (Observe called) so its EWMA includes it.
func FromEvent(e model.Event, f features.NameFeatures, rate *features.RateTracker) Observation {
	o := Observation{
		At:           e.Time,
		NameLength:   float64(f.TotalLength),
		LongestLabel: float64(f.LongestLabel),
		LabelEntropy: f.LongestLabelEntropy,
		LabelDigit:   f.LongestLabelDigit,
		Entropy:      f.Entropy,
		DigitRatio:   f.DigitRatio,
	}
	if rate != nil {
		o.RatePerSec = rate.RatePerSecond()
		o.IntervalMS = rate.MeanIntervalMS()
	}
	if e.Response != nil {
		o.AnswerBytes = float64(e.Response.AnswerBytes)
		o.IPCount = float64(e.Response.IPCount)
		if e.Response.NXDOMAIN {
			o.NXDomain = 1
		}
	}
	return o
}

// NameProfile is the baseline for one (client, name) series.
type NameProfile struct {
	Name      string
	Length    *features.Stats
	Entropy   *features.Stats
	Digit     *features.Stats
	Rate      *features.RateTracker
	Answer    *features.Stats
	Interval  *features.Stats
	Samples   int64
	UpdatedAt time.Time
	CreatedAt time.Time
}

func NewNameProfile(name string, at time.Time) *NameProfile {
	return &NameProfile{
		Name:      name,
		Length:    features.NewStats(),
		Entropy:   features.NewStats(),
		Digit:     features.NewStats(),
		Rate:      features.NewRateTracker(),
		Answer:    features.NewStats(),
		Interval:  features.NewStats(),
		CreatedAt: at,
		UpdatedAt: at,
	}
}

// decay applies exponential decay to all stats based on elapsed time.
func (p *NameProfile) decay(tauSec float64, now time.Time) {
	if tauSec <= 0 || p.Samples == 0 || !now.After(p.UpdatedAt) {
		return
	}
	dt := now.Sub(p.UpdatedAt).Seconds()
	factor := math.Exp(-dt / tauSec)
	if factor >= 1 {
		return
	}
	p.Length.ApplyDecay(factor)
	p.Entropy.ApplyDecay(factor)
	p.Digit.ApplyDecay(factor)
	p.Answer.ApplyDecay(factor)
	p.Interval.ApplyDecay(factor)
}

// Observe folds an observation into the profile, applying drift decay
// relative to the observation timestamp first so the update order stays
// deterministic. The distribution stats are label-centric: length,
// entropy and digit ratio describe the payload-carrying longest label.
func (p *NameProfile) Observe(o Observation) {
	p.Length.Add(o.LongestLabel, o.At)
	p.Entropy.Add(o.LabelEntropy, o.At)
	p.Digit.Add(o.LabelDigit, o.At)
	p.Interval.Add(o.IntervalMS, o.At)
	p.Answer.Add(o.AnswerBytes, o.At)
	p.Samples++
	p.UpdatedAt = o.At
}

// ClientBaseline aggregates per-name profiles for one client.
type ClientBaseline struct {
	ClientIP  string
	names     map[string]*NameProfile
	UpdatedAt time.Time
	CreatedAt time.Time
	tauSec    float64
	maxNames  int
}

func NewClientBaseline(ip string, at time.Time) *ClientBaseline {
	return &ClientBaseline{
		ClientIP:  ip,
		names:     make(map[string]*NameProfile),
		CreatedAt: at,
		UpdatedAt: at,
	}
}

func (b *ClientBaseline) Get(name string) (*NameProfile, bool) {
	p, ok := b.names[name]
	return p, ok
}

// GetOrCreate returns the profile for name, creating it on first sight
// while enforcing the per-client cardinality bound.
func (b *ClientBaseline) GetOrCreate(name string, at time.Time) *NameProfile {
	if p, ok := b.names[name]; ok {
		return p
	}
	p := NewNameProfile(name, at)
	b.names[name] = p
	if b.maxNames > 0 && len(b.names) > b.maxNames {
		b.evictOldest()
	}
	return p
}

// Observe returns the profile for name, creating it on first sight,
// and folds the observation in after applying drift decay.
func (b *ClientBaseline) Observe(name string, o Observation) *NameProfile {
	p, ok := b.names[name]
	if !ok {
		p = NewNameProfile(name, o.At)
		b.names[name] = p
		if b.maxNames > 0 && len(b.names) > b.maxNames {
			b.evictOldest()
		}
	} else {
		p.decay(b.tauSec, o.At)
	}
	p.Observe(o)
	b.UpdatedAt = o.At
	return p
}

func (b *ClientBaseline) evictOldest() {
	var oldestName string
	var oldest time.Time
	first := true
	for n, p := range b.names {
		if first || p.UpdatedAt.Before(oldest) {
			oldestName, oldest, first = n, p.UpdatedAt, false
		}
	}
	if oldestName != "" {
		delete(b.names, oldestName)
	}
}

func (b *ClientBaseline) Names() int { return len(b.names) }

// Registry holds baselines for all clients with bounded cardinality.
type Registry struct {
	clients    map[string]*ClientBaseline
	maxNames   int
	maxClients int
	tauSec     float64
}

func NewRegistry(maxClients, maxNames int, tauSec float64) *Registry {
	return &Registry{
		clients:    make(map[string]*ClientBaseline),
		maxNames:   maxNames,
		maxClients: maxClients,
		tauSec:     tauSec,
	}
}

// Client returns the baseline for ip, creating it on first sight and
// enforcing the client cardinality bound via LRU eviction.
func (r *Registry) Client(ip string, at time.Time) *ClientBaseline {
	b, ok := r.clients[ip]
	if ok {
		return b
	}
	b = NewClientBaseline(ip, at)
	b.tauSec = r.tauSec
	b.maxNames = r.maxNames
	r.clients[ip] = b
	if r.maxClients > 0 && len(r.clients) > r.maxClients {
		r.evictOldestClient()
	}
	return b
}

func (r *Registry) evictOldestClient() {
	var oldestIP string
	var oldest time.Time
	first := true
	for ip, b := range r.clients {
		if first || b.UpdatedAt.Before(oldest) {
			oldestIP, oldest, first = ip, b.UpdatedAt, false
		}
	}
	if oldestIP != "" {
		delete(r.clients, oldestIP)
	}
}

// Profile returns the (client, name) profile, creating missing entries.
func (r *Registry) Profile(ip, name string, at time.Time) *NameProfile {
	b := r.Client(ip, at)
	p, ok := b.Get(name)
	if !ok {
		p = NewNameProfile(name, at)
		p.decay(r.tauSec, at)
		b.names[name] = p
		if r.maxNames > 0 && len(b.names) > r.maxNames {
			b.evictOldest()
		}
	}
	return p
}

func (r *Registry) ClientCount() int { return len(r.clients) }

// SetTau updates the drift time constant for all current and future
// client baselines (configuration hot-reload).
func (r *Registry) SetTau(tauSec float64) {
	r.tauSec = tauSec
	for _, b := range r.clients {
		b.tauSec = tauSec
	}
}

// Prune removes clients (and their profiles) not updated since before
// cutoff and returns the number of removed clients.
func (r *Registry) Prune(cutoff time.Time) int {
	removed := 0
	for ip, b := range r.clients {
		if b.UpdatedAt.Before(cutoff) {
			delete(r.clients, ip)
			removed++
		}
	}
	return removed
}
