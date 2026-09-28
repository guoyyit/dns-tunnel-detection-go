package detector

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/config"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/persist"
)

var base = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

func testCfg() *config.Config {
	c := config.Default()
	c.BucketWidthSec = 30
	c.WindowSizeSec = 300 // depth 10
	c.LateToleranceSec = 60
	c.CooldownSec = 600
	c.Thresholds.MinBaselineSamples = 5
	c.Thresholds.MinSustainedBuckets = 3
	c.Thresholds.MinSuspicionScore = 2.0
	c.Thresholds.HighScore = 3.5
	c.Thresholds.CriticalScore = 5.0
	c.Thresholds.MinNameLength = 40
	c.Thresholds.MinRatePerMinute = 20
	return c
}

const alnum = "abcdefghijklmnopqrstuvwxyz0123456789"

func randName(rng *rand.Rand, n int, suffix string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alnum[rng.Intn(len(alnum))]
	}
	return string(b) + "." + suffix
}

type feed struct {
	d   *Detector
	now time.Time
}

// tunnelEvents emits n tunnel-like events (long high-entropy labels,
// NXDOMAIN, tiny answers) spaced gap apart starting at start.
func (f *feed) tunnelEvents(ip, suffix string, n int, gap time.Duration, start time.Time, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i) * gap)
		if ts.After(f.now) {
			f.now = ts
		}
		f.d.Ingest(model.Event{
			Time: ts, ClientIP: ip, Name: randName(rng, 55, suffix),
			Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 12},
		})
	}
}

func normalEvents(f *feed, ip, zone string, n int, gap time.Duration, start time.Time) {
	names := []string{"www", "mail", "api", "cdn", "news"}
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i) * gap)
		if ts.After(f.now) {
			f.now = ts
		}
		f.d.Ingest(model.Event{
			Time: ts, ClientIP: ip, Name: names[i%len(names)] + "." + zone,
			Response: &model.DNSResponse{Observed: true, IPCount: 2, AnswerBytes: 140, TTL: 60},
		})
	}
}

func collect() (chan model.AlertUpdate, *[]model.AlertUpdate, *sync.Mutex) {
	ch := make(chan model.AlertUpdate, 1024)
	var mu sync.Mutex
	var got []model.AlertUpdate
	return ch, &got, &mu
}

func drain(ch chan model.AlertUpdate) []model.AlertUpdate {
	var out []model.AlertUpdate
	for {
		select {
		case u := <-ch:
			out = append(out, u)
		default:
			return out
		}
	}
}

func countKind(us []model.AlertUpdate, k model.AlertUpdateKind) int {
	n := 0
	for _, u := range us {
		if u.Kind == k {
			n++
		}
	}
	return n
}

// TestFeatureCombinationTriggersTunnel feeds sustained encoded traffic
// and expects a tunnel alert; normal short names must not alert.
func TestFeatureCombinationTriggersTunnel(t *testing.T) {
	cfg := testCfg()
	ch, _, _ := collect()
	d := New(cfg, 2, ch)
	d.SetClock(func() time.Time { return base })
	f := feed{d: d, now: base}

	// Sustained tunnel: 120 events over ~4 min (30/min), each encoded.
	f.tunnelEvents("10.0.0.9", "tun.evil.test", 120, 2*time.Second, base, 1)
	// Sustained normal traffic at comparable rate for a different client.
	normalEvents(&f, "10.0.0.1", "safe.example.com", 120, 2*time.Second, base)

	d.AdvanceTest(f.now)
	us := drain(ch)
	raised := countKind(us, model.AlertRaised)
	if raised != 1 {
		t.Fatalf("expected exactly 1 raised alert, got %d (%+v)", raised, summarize(us))
	}
	a := us[0].Alert
	if a.ClientIP != "10.0.0.9" || a.Name != "evil.test" {
		t.Fatalf("alert identity wrong: %+v", a)
	}
	if a.Severity < model.SeverityMedium {
		t.Fatalf("severity too low: %s", a.Severity)
	}
	if d.Stats().Whitelisted != 0 {
		t.Fatal("nothing whitelisted here")
	}
}

func summarize(us []model.AlertUpdate) []string {
	var s []string
	for _, u := range us {
		s = append(s, u.Alert.ClientIP+"/"+u.Alert.Name+"/"+u.Alert.Severity.String())
	}
	return s
}

// TestSingleAnomalyDoesNotAlert verifies occasional anomalies are
// tolerated: a handful of long encoded names amid normal traffic must
// stay silent.
func TestSingleAnomalyDoesNotAlert(t *testing.T) {
	cfg := testCfg()
	ch, _, _ := collect()
	d := New(cfg, 1, ch)
	f := feed{d: d, now: base}

	// Mostly normal, with a few isolated odd queries (1 per minute,
	// spread across the window so no sustained run forms).
	normalEvents(&f, "10.0.0.1", "safe.example.com", 200, time.Second, base)
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		d.Ingest(model.Event{Time: ts, ClientIP: "10.0.0.1",
			Name:     randName(rng, 55, "odd.example.net"),
			Response: &model.DNSResponse{Observed: true, AnswerBytes: 140}})
	}
	d.AdvanceTest(f.now.Add(time.Minute))
	if us := drain(ch); len(us) != 0 {
		t.Fatalf("occasional anomalies must not alert, got %v", summarize(us))
	}
}

var _ = persist.NewEmpty

// TestCooldownDedupAndReopen: within cooldown repeats are one valid
// alert; after cooldown expiry a sustained condition reopens with a new
// distinguishable alert.
func TestCooldownDedupAndReopen(t *testing.T) {
	cfg := testCfg()
	cfg.CooldownSec = 120
	ch, _, _ := collect()
	d := New(cfg, 1, ch)
	f := feed{d: d, now: base}

	f.tunnelEvents("c", "z.tun.test", 150, 2*time.Second, base, 11)
	d.AdvanceTest(f.now)
	first := drain(ch)
	if countKind(first, model.AlertRaised) != 1 {
		t.Fatalf("want 1 raise, got %d", countKind(first, model.AlertRaised))
	}
	id := first[0].Alert.ID

	// Continue tunnelling and evaluate repeatedly inside cooldown: only
	// suppressions, never a second valid alert.
	f.tunnelEvents("c", "z.tun.test", 60, 2*time.Second, f.now.Add(time.Second), 12)
	d.AdvanceTest(f.now)
	mid := drain(ch)
	for _, u := range mid {
		if u.Kind == model.AlertRaised || u.Kind == model.AlertReopened {
			t.Fatalf("no new valid alert allowed inside cooldown: %v", u.Kind)
		}
	}
	if countKind(mid, model.AlertRepeatedSuppressed) == 0 {
		t.Fatal("expected suppressions inside cooldown")
	}

	// After cooldown expires while the attack persists -> reopen, new ID.
	later := f.now.Add(130 * time.Second)
	d.AdvanceTest(later)
	re := drain(ch)
	reopens := 0
	var reopen model.AlertUpdate
	for _, u := range re {
		if u.Kind == model.AlertReopened {
			reopens++
			reopen = u
		}
	}
	if reopens != 1 {
		t.Fatalf("want exactly 1 reopen after cooldown, got %d (%v)", reopens, summarize(re))
	}
	if reopen.Alert.ID == id {
		t.Fatal("reopen must have a new distinguishable alert ID")
	}
}

// TestSeverityEscalation: a stronger sustained tunnel raises severity
// and emits a SeverityChanged alert.
func TestSeverityEscalation(t *testing.T) {
	cfg := testCfg()
	// Start near the low end with sparse-ish traffic, then flood.
	cfg.Thresholds.MinSuspicionScore = 2.0
	cfg.Thresholds.HighScore = 4.0
	cfg.Thresholds.CriticalScore = 5.2
	ch, _, _ := collect()
	d := New(cfg, 1, ch)
	f := feed{d: d, now: base}
	// First stage: sparse enough to stay below the rate floor
	// (12/min < 20/min); only structural features drive it to medium.
	f.tunnelEvents("c", "z.tun.test", 90, 5*time.Second, base, 21)
	d.AdvanceTest(f.now)
	first := drain(ch)
	sev0 := first[0].Alert.Severity

	// Much denser, longer-payload sustained flood -> higher score.
	rng := rand.New(rand.NewSource(22))
	stageStart := f.now
	for i := 0; i < 2400; i++ {
		ts := stageStart.Add(time.Duration(i) * 150 * time.Millisecond)
		f.now = ts
		d.Ingest(model.Event{Time: ts, ClientIP: "c",
			Name:     randName(rng, 63, "z.tun.test"),
			Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 8}})
		if i%200 == 0 {
			d.AdvanceTest(ts)
		}
	}
	d.AdvanceTest(f.now)
	us := drain(ch)
	esc := countKind(us, model.AlertSeverityChanged)
	if sev0 >= model.SeverityCritical {
		t.Fatalf("test setup should start below critical, got %s", sev0)
	}
	if esc == 0 {
		t.Fatalf("expected a severity escalation from %s, updates=%v", sev0, summarize(us))
	}
	var maxSev model.Severity
	for _, u := range us {
		if u.Kind == model.AlertSeverityChanged && u.Alert.Severity > maxSev {
			maxSev = u.Alert.Severity
		}
	}
	if maxSev <= sev0 {
		t.Fatalf("escalated severity %s must exceed initial %s", maxSev, sev0)
	}
}

// TestWhitelistAndExemption: whitelisted traffic is fully ignored;
// exempt (heartbeat/batch) traffic never alerts even when anomalous.
func TestWhitelistAndExemption(t *testing.T) {
	cfg := testCfg()
	cfg.Whitelist = []config.Rule{{NameSuffix: "trusted.test"}}
	cfg.Exemptions = []config.Rule{{NameSuffix: "heartbeat.internal"}}
	ch, _, _ := collect()
	d := New(cfg, 1, ch)
	f := feed{d: d, now: base}

	// Whitelisted zone firing tunnel-shaped traffic: nothing.
	f.tunnelEvents("c", "a.trusted.test", 200, time.Second, base, 31)
	// Exempt heartbeat with long encoded names: baselined, no alerts.
	rng := rand.New(rand.NewSource(32))
	for i := 0; i < 200; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		f.now = ts
		d.Ingest(model.Event{Time: ts, ClientIP: "c",
			Name:     randName(rng, 55, "h.heartbeat.internal"),
			Response: &model.DNSResponse{Observed: true, AnswerBytes: 10}})
	}
	d.AdvanceTest(f.now)
	if us := drain(ch); len(us) != 0 {
		t.Fatalf("whitelisted/exempt traffic must not alert: %v", summarize(us))
	}
	if d.Stats().Whitelisted == 0 {
		t.Fatal("whitelisted events must be counted")
	}
}

// TestLateAndOutOfOrder: scrambled and slightly late events must still
// accumulate coherently; events beyond tolerance are rejected/counted
// and never corrupt window state.
func TestLateAndOutOfOrder(t *testing.T) {
	cfg := testCfg()
	ch, _, _ := collect()
	d := New(cfg, 1, ch)
	start := base
	rng := rand.New(rand.NewSource(41))

	// Build events in order then shuffle timestamps for ingestion.
	var evs []model.Event
	for i := 0; i < 150; i++ {
		ts := start.Add(time.Duration(i) * 2 * time.Second)
		evs = append(evs, model.Event{Time: ts, ClientIP: "c",
			Name:     randName(rng, 55, "z.tun.test"),
			Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 10}})
	}
	sh := rand.New(rand.NewSource(99))
	sh.Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
	var latest time.Time
	for _, e := range evs {
		if e.Time.After(latest) {
			latest = e.Time
		}
		d.Ingest(e)
	}
	d.AdvanceTest(latest)
	us := drain(ch)
	if countKind(us, model.AlertRaised) != 1 {
		t.Fatalf("out-of-order tunnel must still yield exactly one alert, got %d (%v)",
			countKind(us, model.AlertRaised), summarize(us))
	}

	// A very late event far behind the horizon must be rejected.
	late := start.Add(-time.Hour)
	before := d.Stats().RejectedLate
	d.Ingest(model.Event{Time: late, ClientIP: "c", Name: "z.tun.test",
		Response: &model.DNSResponse{Observed: true}})
	d.AdvanceTest(latest)
	if d.Stats().RejectedLate <= before {
		t.Fatal("over-late event must be counted as rejected")
	}
}

// TestRestartRecovery: snapshot -> new detector -> restore must keep
// the fired-alert cooldown (no duplicate alert) and preserve window
// accumulation (a sustained anomaly spanning restart still escalates/
// reopens exactly per cooldown semantics, never silently lost).
func TestRestartRecovery(t *testing.T) {
	cfg := testCfg()
	cfg.CooldownSec = 300
	path := "" // in-memory snapshot object; persistence file tested in persist pkg
	_ = path

	ch1, _, _ := collect()
	d1 := New(cfg, 1, ch1)
	f := feed{d: d1, now: base}
	f.tunnelEvents("c", "z.tun.test", 150, 2*time.Second, base, 51)
	d1.AdvanceTest(f.now)
	us1 := drain(ch1)
	if countKind(us1, model.AlertRaised) != 1 {
		t.Fatalf("first detector should raise once: %v", summarize(us1))
	}
	snap := d1.Snapshot(f.now)
	if len(snap.Alerts) != 1 || len(snap.Windows) != 1 {
		t.Fatalf("snapshot should contain 1 alert and 1 window, got %d/%d",
			len(snap.Alerts), len(snap.Windows))
	}

	// Simulate restart shortly after (inside cooldown) and keep the
	// attack continuously running across the restart boundary and past
	// cooldown expiry: no duplicate raise while in cooldown, exactly one
	// reopen once it elapses (sustained state was not lost).
	ch2, _, _ := collect()
	d2 := New(cfg, 1, ch2)
	d2.SetClock(func() time.Time { return f.now })
	d2.Restore(snap)

	rng2 := rand.New(rand.NewSource(52))
	// One event every 2s from f.now to f.now+320s: the anomaly is present
	// in buckets covering the whole cooldown window.
	cursor := f.now
	end := f.now.Add(320 * time.Second)
	i := 0
	for cursor.Before(end) {
		cursor = cursor.Add(2 * time.Second)
		d2.Ingest(model.Event{Time: cursor, ClientIP: "c",
			Name:     randName(rng2, 55, "z.tun.test"),
			Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 10}})
		// Evaluate periodically but only inspect the final outcome.
		if i%60 == 0 {
			d2.AdvanceTest(cursor)
		}
		i++
	}
	d2.AdvanceTest(cursor)
	all := drain(ch2)
	var raised, reopen int
	for _, u := range all {
		switch u.Kind {
		case model.AlertRaised:
			raised++
		case model.AlertReopened:
			reopen++
		}
	}
	if raised != 0 {
		t.Fatalf("restart inside cooldown must not raise a duplicate, got %d", raised)
	}
	if reopen != 1 {
		t.Fatalf("expected exactly one reopen after cross-restart cooldown, got %d (%v)",
			reopen, summarize(all))
	}
}

// TestConcurrentIngestion races many goroutines; inline (pre-Start)
// processing is shard-lock serialized and must complete without races.
func TestConcurrentIngestion(t *testing.T) {
	cfg := testCfg()
	d := New(cfg, 8, nil)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 200; i++ {
				ip := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}[g%4]
				ts := base.Add(time.Duration(g*200+i) * 300 * time.Millisecond)
				d.Ingest(model.Event{Time: ts, ClientIP: ip,
					Name:     randName(rng, 50, "x.tun.test"),
					Response: &model.DNSResponse{Observed: true, AnswerBytes: 10}})
			}
		}(g)
	}
	wg.Wait()
	d.AdvanceTest(base.Add(time.Hour))
	if d.Stats().Ingested != 16*200 {
		t.Fatalf("ingested count mismatch: %d", d.Stats().Ingested)
	}
}

// TestConfigHotReloadNoMixedRules: swapping config changes future
// decisions without panicking and bumps the generation; exemptions added
// via reload immediately silence a previously firing zone.
func TestConfigHotReloadNoMixedRules(t *testing.T) {
	cfg := testCfg()
	ch, _, _ := collect()
	d := New(cfg, 1, ch)
	f := feed{d: d, now: base}
	f.tunnelEvents("c", "z.tun.test", 150, 2*time.Second, base, 61)
	d.AdvanceTest(f.now)
	if countKind(drain(ch), model.AlertRaised) != 1 {
		t.Fatal("expected initial alert")
	}
	g1 := d.cfgStore.Current().Generation()

	cfg2 := testCfg()
	cfg2.Exemptions = []config.Rule{{NameSuffix: "z.tun.test"}}
	if err := d.UpdateConfig(cfg2); err != nil {
		t.Fatal(err)
	}
	if d.cfgStore.Current().Generation() <= g1 {
		t.Fatal("config generation must advance")
	}
	// Continue: zone now exempt, no further valid alerts even at reopen.
	f.tunnelEvents("c", "z.tun.test", 200, 2*time.Second, f.now.Add(time.Second), 62)
	d.AdvanceTest(f.now.Add(400 * time.Second))
	for _, u := range drain(ch) {
		if u.Kind == model.AlertRaised || u.Kind == model.AlertReopened ||
			u.Kind == model.AlertSeverityChanged {
			t.Fatalf("newly exempt zone must stay silent, got kind %d", u.Kind)
		}
	}
}

// TestThresholdBoundary: traffic just under the sustained-bucket
// requirement stays silent; crossing the boundary alerts.
func TestThresholdBoundary(t *testing.T) {
	// depth 10 buckets over 300s. Build a burst that fills only
	// MinSustainedBuckets-1 buckets and confirm silence, then extend it
	// across the boundary and confirm an alert.
	mk := func() (*Detector, chan model.AlertUpdate, time.Time) {
		cfg := testCfg()
		cfg.Thresholds.MinSustainedBuckets = 4
		ch := make(chan model.AlertUpdate, 64)
		d := New(cfg, 1, ch)
		return d, ch, base
	}

	// Sub-boundary: events concentrated into 3 buckets (~90s) then quiet.
	d, ch, start := mk()
	rng := rand.New(rand.NewSource(71))
	now := start
	for i := 0; i < 60; i++ { // 60 events *1s spread over ~3 buckets
		ts := start.Add(time.Duration(i) * time.Second)
		now = ts
		d.Ingest(model.Event{Time: ts, ClientIP: "c", Name: randName(rng, 55, "z.tun.test"),
			Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 8}})
	}
	d.AdvanceTest(now.Add(6 * time.Minute))
	if us := drain(ch); countKind(us, model.AlertRaised) != 0 {
		t.Fatalf("sub-boundary burst must not alert: %v", summarize(us))
	}

	// Boundary-crossing: spread the same intensity over >=4 buckets.
	d2, ch2, start2 := mk()
	rng2 := rand.New(rand.NewSource(72))
	now2 := start2
	for i := 0; i < 130; i++ { // spans ~5 buckets at 1s spacing
		ts := start2.Add(time.Duration(i) * time.Second)
		now2 = ts
		d2.Ingest(model.Event{Time: ts, ClientIP: "c", Name: randName(rng2, 55, "z.tun.test"),
			Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 8}})
	}
	d2.AdvanceTest(now2)
	if countKind(drain(ch2), model.AlertRaised) != 1 {
		t.Fatal("sustained burst crossing the bucket boundary must alert once")
	}
}

// TestRunningModeAndPersistenceFile exercises the full Start path with
// the wall clock: events through bounded shard mailboxes, ticker-driven
// window advancement, and atomic snapshot persistence to a real file.
func TestRunningModeAndPersistenceFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/state.json"

	cfg := testCfg()
	cfg.BucketWidthSec = 1
	cfg.WindowSizeSec = 10
	cfg.LateToleranceSec = 2
	cfg.PersistPath = path
	cfg.PersistPeriodMS = 200

	ch := make(chan model.AlertUpdate, 64)
	d := New(cfg, 2, ch)
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)

	rng := rand.New(rand.NewSource(81))
	start := time.Now()
	// Emit ~15s of sustained tunnel traffic at ~20/s through mailboxes.
	deadline := start.Add(8 * time.Second)
	i := 0
	for time.Now().Before(deadline) {
		d.Ingest(model.Event{Time: time.Now(), ClientIP: "c",
			Name:     randName(rng, 55, "z.tun.test"),
			Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 8}})
		i++
		if i%40 == 0 {
			time.Sleep(20 * time.Millisecond) // let the shard drain
		}
	}

	// Wait until the alert shows up (ticker-driven) or time out.
	deadlineCh := time.After(8 * time.Second)
	gotRaise := false
	for !gotRaise {
		select {
		case u := <-ch:
			if u.Kind == model.AlertRaised {
				gotRaise = true
			}
		case <-deadlineCh:
			t.Fatal("running mode did not raise an alert in time")
		}
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()

	// The state file must exist and be reloadable with content.
	s, err := persist.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Alerts) == 0 {
		t.Fatal("persisted state should include the fired alert")
	}
	if len(s.Windows) == 0 {
		t.Fatal("persisted state should include window state")
	}
}

// TestBoundedMailboxDropsUnderOverload ensures non-blocking ingestion
// never blocks callers and that drops are counted.
func TestBoundedMailboxDropsUnderOverload(t *testing.T) {
	cfg := testCfg()
	d := New(cfg, 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	defer cancel()
	// Flood far beyond the mailbox; the service must survive and count.
	for i := 0; i < mailboxSize*10; i++ {
		d.Ingest(model.Event{Time: time.Now(), ClientIP: "c", Name: "x.test"})
	}
	st := d.Stats()
	if st.Ingested+st.Dropped != int64(mailboxSize*10) {
		t.Fatalf("every event must be accepted or counted as dropped: %+v", st)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}
