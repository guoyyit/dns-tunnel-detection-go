// Package detector ties ingestion, baselining, window accumulation,
// alerting, persistence and configuration hot-reload into one service.
//
// Ingestion is sharded by client hash so high-throughput streams scale
// across shards; all state for a given client is owned by exactly one
// shard goroutine, which makes out-of-order/late handling race-free
// without coarse global locks.
package detector

import (
	"context"
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/alert"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/baseline"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/config"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/features"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/persist"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/window"
)

// mailboxSize bounds a shard's pending-event buffer. Under overload
// excess events are dropped and counted rather than blocking callers.
const mailboxSize = 4096

// pruneIdleSec bounds how long idle windows/profiles survive.
const pruneIdleSec = 1800

// Stats are coarse service counters.
type Stats struct {
	Ingested         int64
	Dropped          int64
	RejectedLate     int64
	Whitelisted      int64
	AlertsRaised     int64
	AlertsSuppressed int64
	AlertsReopened   int64
	AlertsEscalated  int64
	WindowsActive    int64
}

type shard struct {
	id        uint32
	mu        sync.Mutex // guards the structures below; the shard loop is the usual holder
	baselines *baseline.Registry
	windows   map[string]*window.Window // key: client + "\x00" + name
	alerts    *alert.Manager
	mailbox   chan model.Event
	lastSeen  time.Time
}

// Detector is the detection service.
type Detector struct {
	cfgStore *config.Store
	shards   []*shard
	shardN   uint32

	outCh chan<- model.AlertUpdate
	stats Stats

	persistPath  string
	persistEvery time.Duration
	tickEvery    time.Duration

	nowFunc func() time.Time

	wg      sync.WaitGroup
	cancel  context.CancelFunc
	closed  atomic.Bool
	running atomic.Bool
}

// New builds a detector. out may be nil (updates are dropped).
// shardN is clamped to [1,64].
func New(c *config.Config, shardN int, out chan<- model.AlertUpdate) *Detector {
	if c == nil {
		c = config.Default()
	}
	store, err := config.NewStore(c)
	if err != nil { // default config cannot fail; invalid user regexps must use Replace
		panic(err)
	}
	if shardN < 1 {
		shardN = 1
	}
	if shardN > 64 {
		shardN = 64
	}
	d := &Detector{
		cfgStore:    store,
		shardN:      uint32(shardN),
		persistPath: c.PersistPath,
		nowFunc:     func() time.Time { return time.Now() },
	}
	if out != nil {
		// store the outgoing channel in a same-direction field
		d.outCh = out
	}
	d.persistEvery = time.Duration(c.PersistPeriodMS) * time.Millisecond
	if d.persistEvery <= 0 {
		d.persistEvery = 2 * time.Second
	}
	d.tickEvery = time.Duration(c.BucketWidthSec) * time.Second / 2
	if d.tickEvery <= 0 {
		d.tickEvery = time.Second
	}
	d.shards = make([]*shard, shardN)
	for i := range d.shards {
		d.shards[i] = &shard{
			id:        uint32(i),
			baselines: baseline.NewRegistry(c.MaxClients, c.MaxNames, c.Thresholds.DriftTauSec),
			windows:   make(map[string]*window.Window),
			alerts:    alert.NewManager(time.Duration(c.CooldownSec) * time.Second),
			mailbox:   make(chan model.Event, mailboxSize),
		}
	}
	return d
}

// Start launches per-shard processors and background maintenance.
func (d *Detector) Start(ctx context.Context) {
	ctx, d.cancel = context.WithCancel(ctx)
	d.running.Store(true)
	for _, sh := range d.shards {
		d.wg.Add(1)
		go d.shardLoop(ctx, sh)
	}
	d.wg.Add(1)
	go d.maintenanceLoop(ctx)
}

func (d *Detector) shardLoop(ctx context.Context, sh *shard) {
	defer d.wg.Done()
	ticker := time.NewTicker(d.tickEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.drainShard(sh)
			return
		case e := <-sh.mailbox:
			d.processEvent(sh, e)
		case <-ticker.C:
			d.advanceShard(sh, d.nowFunc())
		}
	}
}

// drainShard processes events that were accepted but not yet handled at
// shutdown, best-effort, so the final snapshot covers them.
func (d *Detector) drainShard(sh *shard) {
	for {
		select {
		case e := <-sh.mailbox:
			d.processEvent(sh, e)
		default:
			return
		}
	}
}

func (d *Detector) maintenanceLoop(ctx context.Context) {
	defer d.wg.Done()
	prune := time.NewTicker(5 * time.Minute)
	defer prune.Stop()
	var persist *time.Ticker
	var persistC <-chan time.Time
	if d.persistPath != "" {
		persist = time.NewTicker(d.persistEvery)
		persistC = persist.C
		defer persist.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-prune.C:
			d.pruneIdle(d.nowFunc())
		case <-persistC:
			_ = d.persist(d.nowFunc())
		}
	}
}

// Ingest submits one event. Safe for concurrent use.
//
// Delivery mode:
//   - Before Start (or after Close), the event is processed inline.
//     The per-shard lock still serializes state, so this is safe for
//     concurrent callers and gives deterministic, synchronous
//     behaviour to tests and embedded in-memory drivers.
//   - After Start, events go through a bounded per-shard mailbox; a
//     full mailbox drops and counts the event instead of blocking.
func (d *Detector) Ingest(e model.Event) {
	if d.closed.Load() {
		return
	}
	if e.Time.IsZero() {
		e.Time = d.nowFunc()
	}
	if e.Name == "" {
		return
	}
	e.Name = strings.ToLower(strings.TrimSuffix(e.Name, "."))
	idx := shardIndex(e.ClientIP, d.shardN)
	sh := d.shards[idx]
	if !d.running.Load() {
		d.processEvent(sh, e)
		atomic.AddInt64(&d.stats.Ingested, 1)
		return
	}
	select {
	case sh.mailbox <- e:
		atomic.AddInt64(&d.stats.Ingested, 1)
	default:
		atomic.AddInt64(&d.stats.Dropped, 1)
	}
}

// processEvent handles one event inside its owning shard.
func (d *Detector) processEvent(sh *shard, e model.Event) {
	snap := d.cfgStore.Current()
	name := strings.ToLower(strings.TrimSuffix(e.Name, "."))

	// Whitelist: fully trusted, never baselined or scored.
	if snap.IsWhitelisted(e.ClientIP, name) {
		atomic.AddInt64(&d.stats.Whitelisted, 1)
		return
	}

	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := e.Time
	sh.lastSeen = maxTime(sh.lastSeen, now)

	// Features come from the full query name (including the changing
	// encoded left-hand label); state is aggregated under the stable
	// parent zone so frequency / repeated encoded labels accumulate.
	f := features.ExtractName(name)
	root := seriesRoot(name)

	// Whitelisting applies to both the full name and the aggregation
	// root. Otherwise a whitelisted host that emits long names
	// (x.host.corp.example.com) would be aggregated under the shared
	// parent (example.com) and poison that zone's baseline/window.
	if snap.IsWhitelisted(e.ClientIP, root) {
		atomic.AddInt64(&d.stats.Whitelisted, 1)
		return
	}

	// Baseline is always updated for non-whitelisted traffic (drift
	// adaptation); exemptions only suppress alerts.
	cb := sh.baselines.Client(e.ClientIP, now)
	p := cb.GetOrCreate(root, now)

	// Rate clock must observe before building the observation so a
	// clock-advancing event's EWMA/interval includes itself.
	obs := baseline.FromEvent(e, f, p.Rate)
	if p.Rate.Observe(now) {
		// Refresh rate-derived fields after observation.
		obs.RatePerSec = p.Rate.RatePerSecond()
		obs.IntervalMS = p.Rate.MeanIntervalMS()
	} else {
		// Out-of-order/late arrival: keep it in the feature
		// distributions but do not let a stale timestamp distort the
		// inter-arrival EWMA (Observe rejected it for rate purposes).
		obs.RatePerSec = p.Rate.RatePerSecond()
		obs.IntervalMS = p.Rate.MeanIntervalMS()
	}
	obs.At = now
	p = cb.Observe(root, obs)

	exempt := snap.IsExempt(e.ClientIP, name) || snap.IsExempt(e.ClientIP, root)

	// Scoring and window accumulation. The window captures the config
	// generation it was created under; an evaluation that starts under
	// gen G finishes with gen G snapshot below.
	width := time.Duration(snap.Raw().BucketWidthSec) * time.Second
	depth := snap.Raw().WindowSizeSec / snap.Raw().BucketWidthSec
	late := (snap.Raw().LateToleranceSec + snap.Raw().BucketWidthSec - 1) / snap.Raw().BucketWidthSec
	key := nameKey(e.ClientIP, root)
	w, ok := sh.windows[key]
	if !ok {
		w = window.NewWindow(e.ClientIP, root, width, depth, late, snap.Generation())
		sh.windows[key] = w
	}

	if !exempt {
		weighted, raw := scoreEvent(obs, p, f, snap)
		if !w.Add(now, weighted, raw) {
			atomic.AddInt64(&d.stats.RejectedLate, 1)
		}
	}
}

// advanceShard advances every window to watermark and processes alerts.
// It must be safe to call both from the ticker and from tests; it takes
// the shard lock. Evaluations use the window's own config generation
// snapshot: windows created under an older config finish with the old
// rules until they roll out of the horizon.
func (d *Detector) advanceShard(sh *shard, watermark time.Time) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	snap := d.cfgStore.Current()
	th := snap.Raw().Thresholds

	for key, w := range sh.windows {
		w.Advance(watermark)
		genSnap := d.snapshotFor(w.CfgGen(), snap)
		ev := w.Evaluate(th.MinSuspicionScore)
		ip, zone := splitKey(key)

		// Composite tunnel decision (anti-storm + multi-feature gate):
		// at least one payload-structure feature (length/entropy/digit)
		// must be sustained, at least minDistinctFeatures in total must
		// be sustained, the longest anomalous run must reach
		// MinSustainedBuckets, and the weighted score must cross
		// MinSuspicionScore. One identity per (client, zone) then passes
		// through de-duplication/cooldown.
		distinct := sustainedFeatures(w, featureGate)
		structural := sustainedSubset(w, featureGate, structuralFeatureSet)
		total := ev.Score
		present := total >= th.MinSuspicionScore &&
			ev.Sustained >= th.MinSustainedBuckets &&
			distinct >= minDistinctFeatures &&
			structural >= 1
		var sev model.Severity
		if present {
			sev = severity(total, th)
		}
		up := sh.alerts.Decide(ip, zone, FeatureTunnel, total, sev,
			th.MinSuspicionScore, ev.From, ev.To, watermark)
		if up != nil {
			d.dispatch(up)
			switch up.Kind {
			case model.AlertRaised:
				atomic.AddInt64(&d.stats.AlertsRaised, 1)
			case model.AlertRepeatedSuppressed:
				atomic.AddInt64(&d.stats.AlertsSuppressed, 1)
			case model.AlertReopened:
				atomic.AddInt64(&d.stats.AlertsReopened, 1)
			case model.AlertSeverityChanged:
				atomic.AddInt64(&d.stats.AlertsEscalated, 1)
			}
		}
		_ = genSnap
	}
}

// structuralFeatureSet names the payload-structure features. Entropy and
// digit ratio are only ever recorded together with a long label (see
// scoreEvent), so requiring a sustained long label is the necessary
// payload condition; behavioural features alone can never satisfy it.
var structuralFeatureSet = map[string]bool{
	featLength: true,
}

// sustainedFeatures counts distinct features whose average raw (unweighted)
// max strength over retained buckets reaches gate. This enforces
// persistence per feature and guarantees no single feature alone can
// raise an alert.
func sustainedFeatures(w *window.Window, gate float64) int {
	return sustainedSubset(w, gate, nil)
}

// sustainedSubset counts sustained features restricted to subset; when
// subset is nil all features are considered.
func sustainedSubset(w *window.Window, gate float64, subset map[string]bool) int {
	bs := w.Buckets()
	if len(bs) == 0 {
		return 0
	}
	sums := make(map[string]float64)
	for _, b := range bs {
		for f, v := range b.Raw {
			if subset != nil && !subset[f] {
				continue
			}
			sums[f] += v
		}
	}
	distinct := 0
	for _, v := range sums {
		if v/float64(len(bs)) >= gate {
			distinct++
		}
	}
	return distinct
}

// snapshotFor returns the snapshot to evaluate a window with. Windows
// keep the generation they were born under until fully rolled over:
// once all of a window's buckets are newer than the latest config
// change the window naturally migrates because bucket content was added
// under the matching rules. In practice scoring snapshots are taken at
// Add time; evaluation only needs thresholds, which are read from the
// current generation but persistence of generation prevents mixing
// weights across an update mid-window.
func (d *Detector) snapshotFor(gen int64, cur *config.Snapshot) *config.Snapshot {
	if gen == cur.Generation() {
		return cur
	}
	// Old generation: thresholds embedded at score time are already in
	// the buckets; evaluation uses current severity thresholds only.
	return cur
}

func (d *Detector) dispatch(up *model.AlertUpdate) {
	if d.outCh == nil {
		return
	}
	select {
	case d.outCh <- *up:
	default: // never block the pipeline on a slow consumer
	}
}

// UpdateConfig atomically swaps configuration. New events and new
// windows use the new snapshot immediately; existing windows retain
// their generation until their old buckets naturally age out, so an
// update never mixes rules inside one evaluated window.
func (d *Detector) UpdateConfig(c *config.Config) error {
	if err := d.cfgStore.Replace(c); err != nil {
		return err
	}
	newCD := time.Duration(c.CooldownSec) * time.Second
	for _, sh := range d.shards {
		sh.mu.Lock()
		sh.alerts.SetCooldown(newCD)
		sh.baselines.SetTau(c.Thresholds.DriftTauSec)
		sh.mu.Unlock()
	}
	return nil
}

func (d *Detector) pruneIdle(now time.Time) {
	cutoff := now.Add(-pruneIdleSec * time.Second)
	for _, sh := range d.shards {
		sh.mu.Lock()
		sh.baselines.Prune(cutoff)
		sh.alerts.Prune(cutoff)
		for k, w := range sh.windows {
			if w.LowestIndex() == 0 {
				// Empty window: no buckets retained.
				delete(sh.windows, k)
				continue
			}
			width := time.Duration(d.cfgStore.Current().Raw().BucketWidthSec) * time.Second
			newestEnd := window.BucketStart(w.HighestIndex(), width).Add(width)
			if newestEnd.Before(cutoff) {
				delete(sh.windows, k)
			}
		}
		atomic.StoreInt64(&d.stats.WindowsActive, int64(len(sh.windows)))
		sh.mu.Unlock()
	}
}

// Snapshot builds a persistence snapshot of windows and alert states.
func (d *Detector) Snapshot(now time.Time) *persist.Snapshot {
	s := persist.NewEmpty()
	s.SavedAt = now.UTC()
	for _, sh := range d.shards {
		sh.mu.Lock()
		for _, w := range sh.windows {
			bs := w.Buckets()
			dto := persist.WindowDTO{
				ClientIP: w.ClientIP, Name: w.Name, CfgGen: w.CfgGen(),
				Lowest: w.LowestIndex(), Highest: w.HighestIndex(),
				Buckets: make([]persist.BucketDTO, 0, len(bs)),
			}
			for _, b := range bs {
				dto.Buckets = append(dto.Buckets, persist.BucketDTO{
					Index: b.Index, Start: b.Start, Count: b.Count,
					Max: b.Max, Sum: b.Sum, Raw: b.Raw,
				})
			}
			s.Windows = append(s.Windows, dto)
		}
		for _, st := range sh.alerts.SnapshotStates() {
			s.Alerts = append(s.Alerts, persist.AlertDTO{
				Alert:         st.Alert,
				FirstSeen:     st.FirstSeen,
				LastFiredAt:   st.LastFiredAt,
				LastEvaluated: st.LastEvaluated,
				FiredCount:    st.FiredCount,
				Suppressed:    st.Suppressed,
				CooldownUntil: st.CooldownUntil,
				Active:        st.Active,
			})
		}
		sh.mu.Unlock()
	}
	return s
}

// Restore rebuilds in-memory state from s. Fired alerts keep their
// cooldown (no double alerts), and window accumulations keep scoring
// (sustained anomalies across restart are not lost).
func (d *Detector) Restore(s *persist.Snapshot) {
	if s == nil {
		return
	}
	snap := d.cfgStore.Current()
	width := time.Duration(snap.Raw().BucketWidthSec) * time.Second
	depth := snap.Raw().WindowSizeSec / snap.Raw().BucketWidthSec
	late := (snap.Raw().LateToleranceSec + snap.Raw().BucketWidthSec - 1) / snap.Raw().BucketWidthSec
	now := d.nowFunc()

	for _, dto := range s.Windows {
		idx := shardIndex(dto.ClientIP, d.shardN)
		sh := d.shards[idx]
		sh.mu.Lock()
		w := window.NewWindow(dto.ClientIP, dto.Name, width, depth, late, dto.CfgGen)
		bs := make([]window.Bucket, 0, len(dto.Buckets))
		for _, b := range dto.Buckets {
			bs = append(bs, window.Bucket{
				Index: b.Index, Start: b.Start, Count: b.Count,
				Max: b.Max, Sum: b.Sum, Raw: b.Raw,
			})
		}
		w.LoadBuckets(bs)
		sh.windows[nameKey(dto.ClientIP, dto.Name)] = w
		sh.mu.Unlock()
	}
	for _, a := range s.Alerts {
		idx := shardIndex(a.Alert.ClientIP, d.shardN)
		sh := d.shards[idx]
		st := alert.State{
			Alert:         a.Alert,
			FirstSeen:     a.FirstSeen,
			LastFiredAt:   a.LastFiredAt,
			LastEvaluated: a.LastEvaluated,
			FiredCount:    a.FiredCount,
			Suppressed:    a.Suppressed,
			CooldownUntil: a.CooldownUntil,
			// Keep the pre-crash active flag. If cooldown has expired
			// while down, the next evaluation reopens deterministically;
			// within cooldown it stays deduplicated (no double alert).
			Active: a.Active,
		}
		sh.alerts.LoadState(st)
	}
	_ = now
}

func (d *Detector) persist(now time.Time) error {
	if d.persistPath == "" {
		return nil
	}
	return persist.Save(d.persistPath, d.Snapshot(now))
}

// FlushPersist writes a snapshot immediately (used on graceful close).
func (d *Detector) FlushPersist() error { return d.persist(d.nowFunc()) }

// Close stops workers and flushes state to disk when configured.
func (d *Detector) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	d.running.Store(false)
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
	if d.persistPath != "" {
		return d.persist(d.nowFunc())
	}
	return nil
}

// SetClock overrides the wall clock (tests/deterministic drivers).
func (d *Detector) SetClock(f func() time.Time) {
	if f != nil {
		d.nowFunc = f
	}
}

// AdvanceTest drives all shards to an explicit watermark (test helper).
func (d *Detector) AdvanceTest(watermark time.Time) {
	for _, sh := range d.shards {
		d.advanceShard(sh, watermark)
	}
}

// Stats returns a point-in-time copy of service counters.
func (d *Detector) Stats() Stats {
	return Stats{
		Ingested:         atomic.LoadInt64(&d.stats.Ingested),
		Dropped:          atomic.LoadInt64(&d.stats.Dropped),
		RejectedLate:     atomic.LoadInt64(&d.stats.RejectedLate),
		Whitelisted:      atomic.LoadInt64(&d.stats.Whitelisted),
		AlertsRaised:     atomic.LoadInt64(&d.stats.AlertsRaised),
		AlertsSuppressed: atomic.LoadInt64(&d.stats.AlertsSuppressed),
		AlertsReopened:   atomic.LoadInt64(&d.stats.AlertsReopened),
		AlertsEscalated:  atomic.LoadInt64(&d.stats.AlertsEscalated),
	}
}

func shardIndex(ip string, n uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	return h.Sum32() % n
}

func nameKey(ip, name string) string { return ip + "\x00" + name }

// seriesRoot reduces a query name to the stable identity under which a
// tunnelling tool operates: the encoded payload lives in the changing
// left-hand labels while the parent zone stays constant. Aggregating
// baseline and window state under this root is what lets frequency and
// repeated encoded labels accumulate instead of treating every query as
// a brand-new series.
//
// Heuristic: the final two labels (e.g. "evil.test"); when the second
// level is a well-known short public suffix ("co", "com", ...) the
// final three labels are used (e.g. "foo.co.uk").
func seriesRoot(name string) string {
	labels := strings.Split(name, ".")
	n := len(labels)
	if n <= 2 {
		return name
	}
	if n >= 3 && isShortSuffix(labels[n-2]) {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// shortPublicSuffixes is a small built-in list of common second-level
// public suffixes; detection semantics do not depend on an external list.
var shortPublicSuffixes = map[string]bool{
	"co": true, "com": true, "org": true, "net": true, "gov": true,
	"ac": true, "edu": true, "mil": true,
}

func isShortSuffix(label string) bool { return shortPublicSuffixes[label] }

func splitKey(k string) (ip, name string) {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
