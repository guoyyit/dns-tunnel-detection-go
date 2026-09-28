// Package detector wires feature extraction, evolving baselines, sliding
// windows, cooldown management, sharded concurrent ingestion and
// persistence into the DNS tunnel detection engine.
//
// # Concurrency model
//
// Events are hashed to one of N shards by client IP. Each shard owns a
// baseline tracker, a window and an alert manager and is driven by exactly
// one goroutine. All mutable state is therefore lock-free by construction
// and safe under high ingest parallelism. Queues are bounded: when a shard
// backlog fills, Submit returns ErrQueueFull so callers can shed load
// instead of growing memory without limit.
//
// # Determinism
//
// Every time-sensitive decision uses the event timestamp. Feeding the same
// event sequence (possibly out of order) through Ingest always produces
// the same alerts, which is also what makes crash replay exact.
package detector

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/alerting"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/baseline"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/features"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/persist"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/window"
)

// AlertSink receives fired alerts.
type AlertSink func(model.Alert)

// Engine is the concurrent detection service.
type Engine struct {
	cfg   config.Config
	store persist.Store
	sink  AlertSink

	shards []*shard
	wg     sync.WaitGroup

	cfgMu   sync.RWMutex
	wlSnap  *config.Snapshot // current whitelist generation
	scoring config.ScoringConfig
	wincfg  config.WindowConfig

	started atomic.Bool

	snapSeq  int64
	eventCnt atomic.Int64
}

// shard is a single-threaded partition of all mutable state.
type shard struct {
	id        int
	base      *baseline.Tracker
	win       *window.Window
	alerts    *alerting.Manager
	watermark time.Time
	queue     chan model.Event
	eng       *Engine
}

// New builds an engine. A nil store disables persistence.
func New(cfg config.Config, store persist.Store, sink AlertSink) *Engine {
	if sink == nil {
		sink = func(model.Alert) {}
	}
	n := cfg.Ingest.ShardCount
	if n <= 0 {
		n = 8
	}
	e := &Engine{
		cfg:   cfg,
		store: store,
		sink:  sink,
	}
	snap, _ := cfg.Whitelist.Compile(1)
	e.wlSnap = snap
	e.scoring = cfg.Scoring
	e.wincfg = cfg.Window
	e.shards = make([]*shard, n)
	for i := range e.shards {
		e.shards[i] = &shard{
			id:     i,
			base:   baseline.NewTracker(cfg.Baseline, cfg.Window.Slide),
			win:    window.New(cfg.Window),
			alerts: alerting.New(cfg.Cooldown),
			queue:  make(chan model.Event, cfg.Ingest.QueueSize),
			eng:    e,
		}
	}
	return e
}

func shardIndex(ip string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return int(h.Sum32() % uint32(n))
}

func (e *Engine) shardFor(ip string) *shard {
	return e.shards[shardIndex(ip, len(e.shards))]
}

// Start launches shard workers and background maintenance.
func (e *Engine) Start(ctx context.Context) error {
	if !e.started.CompareAndSwap(false, true) {
		return errors.New("detector: already started")
	}
	for _, s := range e.shards {
		e.wg.Add(1)
		go e.runShard(ctx, s)
	}
	e.wg.Add(1)
	go e.maintenance(ctx)
	return nil
}

func (e *Engine) runShard(ctx context.Context, s *shard) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.queue:
			e.apply(s, ev)
		}
	}
}

// Submit enqueues an event. It returns ErrQueueFull under backpressure.
// When persistence is enabled the event is durably logged BEFORE it is
// enqueued, so acceptance implies recoverability.
func (e *Engine) Submit(ev model.Event) error {
	if e.store != nil {
		if err := e.store.WALEntry(ev); err != nil {
			return err
		}
	}
	s := e.shardFor(ev.ClientIP)
	if e.started.Load() {
		select {
		case s.queue <- ev:
		default:
			return ErrQueueFull
		}
	} else {
		// Synchronous mode (tests / replay before Start).
		e.apply(s, ev)
	}
	e.eventCnt.Add(1)
	return nil
}

// Ingest applies an event synchronously on the caller goroutine and
// returns any alerts it produced. It does NOT write the WAL (used during
// recovery replay and for deterministic tests).
func (e *Engine) Ingest(ev model.Event) []model.Alert {
	s := e.shardFor(ev.ClientIP)
	return e.apply(s, ev)
}

// apply is the single stateful event transition; must run on the shard's
// goroutine (or synchronously before Start).
func (e *Engine) apply(s *shard, ev model.Event) []model.Alert {
	// 1) whitelist generation: exemption evaluated atomically per event
	e.cfgMu.RLock()
	wl := e.wlSnap
	e.cfgMu.RUnlock()
	if wl.ExemptClient(ev.ClientIP) || wl.ExemptName(ev.QName) {
		return nil
	}

	ts := ev.TS
	// late events are accepted by the window only within grace; baseline
	// observation is skipped for events older than the shard watermark so
	// out-of-order arrival cannot corrupt evolving statistics.
	later := s.watermark.IsZero() || ts.After(s.watermark)
	if later {
		s.watermark = ts
	}

	f := features.Extract(&ev)

	// Scoring compares against history EXCLUDING this event: read frequency
	// bookkeeping and score first, then update the evolving baseline.
	nb := s.base.Name(ev.QName)
	hits := hitsInCurrentBucket(nb, ts, e.cfg.Window.Slide)
	gapMicros := int64(0)
	if later {
		if cb := s.base.Client(ev.ClientIP); cb != nil {
			gapMicros = ts.Sub(cb.LastQueryTime()).Microseconds()
		}
	}
	res := score(e.cfg, s.base, &ev, f, gapMicros, hits)

	if later {
		s.base.Observe(&ev, f, ts)
	}

	accepted := s.win.Add(ev.ClientIP, res.key, ts, res.score, res.reasons, ev.QName)
	if !accepted {
		return nil
	}

	var fired []model.Alert
	if res.score > 0 {
		// Only states that just received evidence need re-evaluation, but
		// Evaluate is a cheap bounded scan of in-window states per shard.
		for _, d := range s.win.Evaluate(ts) {
			if !d.Fire {
				continue
			}
			a := s.alerts.Consider(alerting.Candidate{
				Client:     d.Client,
				Key:        d.Key,
				Severity:   model.Severity(d.Severity),
				Score:      d.Score,
				TS:         d.LastTS,
				Reasons:    d.Reasons,
				SampleName: d.SampleName,
			})
			if a != nil {
				fired = append(fired, *a)
				e.sink(*a)
			}
		}
	}

	// opportunistic expiry when time advances
	if later {
		s.alerts.Expire(ts.Add(-e.cfg.Cooldown.Duration))
	}
	return fired
}

// maintenance periodically advances windows and evicts idle state, keeping
// memory bounded during long runs. Timing is wall-clock only for scheduling;
// all cutoff values derive from event timestamps, so results are unaffected
// if maintenance runs early or late.
func (e *Engine) maintenance(ctx context.Context) {
	defer e.wg.Done()
	every := e.cfg.Window.Slide
	if every <= 0 {
		every = 30 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.gc()
			if e.store != nil && e.eventCnt.Load() >= int64(e.cfg.Persistence.SnapshotEvery) {
				if err := e.checkpoint(); err == nil {
					e.eventCnt.Store(0)
				}
			}
		}
	}
}

func (e *Engine) gc() {
	cutoff := e.watermarkGlobal().Add(-e.cfg.Window.Size - e.cfg.Cooldown.Duration)
	for _, s := range e.shards {
		s.win.Advance(s.watermark)
		s.base.Evict(cutoff)
		s.alerts.Expire(s.watermark)
	}
}

func (e *Engine) watermarkGlobal() time.Time {
	var max time.Time
	for _, s := range e.shards {
		if s.watermark.After(max) {
			max = s.watermark
		}
	}
	return max
}

// UpdateConfig installs a new generation of whitelist/scoring rules.
// Existing windows were accumulated under prior rules; they are allowed to
// expire naturally (Advance), so no single window mixes old and new rule
// evidence. New events immediately use the new generation.
func (e *Engine) UpdateConfig(cfg config.Config) error {
	snap, err := cfg.Whitelist.Compile(e.wlSnap.Gen + 1)
	if err != nil {
		return err
	}
	e.cfgMu.Lock()
	e.cfg = cfg
	e.wlSnap = snap
	e.scoring = cfg.Scoring
	e.wincfg = cfg.Window
	e.cfgMu.Unlock()
	// cooldown/window knobs are shard-local; install via per-shard reset of
	// their config values without discarding accumulated state.
	for _, s := range e.shards {
		s.alerts.SetConfig(cfg.Cooldown)
		s.win.SetConfig(cfg.Window)
	}
	return nil
}

// Watermark returns the highest event timestamp observed across shards.
func (e *Engine) Watermark() time.Time { return e.watermarkGlobal() }

// checkpoint writes a full atomic snapshot of all shards.
func (e *Engine) checkpoint() error {
	states := make([]persist.State, 0, len(e.shards))
	for _, s := range e.shards {
		bl, _ := json.Marshal(s.base.Export())
		wn, _ := json.Marshal(s.win.Export())
		al, _ := json.Marshal(s.alerts.Export())
		states = append(states, persist.State{
			Shard:     s.id,
			Watermark: s.watermark.UnixNano(),
			Baseline:  bl,
			Window:    wn,
			Alerting:  al,
		})
	}
	return e.store.SaveSnapshot(states)
}

// Recover loads the newest snapshot and replays post-snapshot WAL events
// through the deterministic pipeline. Sharding is by client IP and stable
// across restarts, so each event lands on the same shard it had before.
func (e *Engine) Recover(ctx context.Context) error {
	if e.store == nil {
		return nil
	}
	states, err := e.store.LoadSnapshot()
	if err != nil {
		return err
	}
	var snapSeq int64
	if len(states) > 0 {
		snapSeq, err = e.store.SnapshotSeq()
		if err != nil {
			return err
		}
	}
	for _, st := range states {
		if st.Shard < 0 || st.Shard >= len(e.shards) {
			continue
		}
		s := e.shards[st.Shard]
		if st.Watermark > 0 {
			s.watermark = time.Unix(0, st.Watermark)
		}
		if len(st.Baseline) > 0 {
			var bs baseline.Snapshot
			if err := json.Unmarshal(st.Baseline, &bs); err == nil {
				s.base.Restore(bs)
			}
		}
		if len(st.Window) > 0 {
			var ws window.Snap
			if err := json.Unmarshal(st.Window, &ws); err == nil {
				s.win.Restore(ws)
			}
		}
		if len(st.Alerting) > 0 {
			var as alerting.Snap
			if err := json.Unmarshal(st.Alerting, &as); err == nil {
				s.alerts.Restore(as)
			}
		}
	}
	return e.store.ReplayWAL(ctx, snapSeq, func(ev model.Event) error {
		e.Ingest(ev)
		return nil
	})
}

// Close checkpoints, flushes and stops.
func (e *Engine) Close() error {
	if e.store != nil {
		if err := e.checkpoint(); err != nil {
			return err
		}
		return e.store.Close()
	}
	return nil
}

// ErrQueueFull is returned when an ingestion queue is saturated.
var ErrQueueFull = errQueueFull{}

type errQueueFull struct{}

func (errQueueFull) Error() string { return "detector: ingestion queue full" }
