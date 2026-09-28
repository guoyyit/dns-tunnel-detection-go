package detector

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/config"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
	"github.com/guoyyit/dns-tunnel-detection-go/internal/persist"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomName(r *rand.Rand, n int, parent string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b) + "." + parent
}

func testConfig() config.Config {
	cfg := config.Default()
	cfg.Window = config.WindowConfig{
		Size:            time.Minute,
		Slide:           10 * time.Second,
		FireScore:       6,
		FireBuckets:     3,
		MaxSuspectScore: 10,
		LatenessGrace:   20 * time.Second,
	}
	cfg.Scoring.NameLenAbsThreshold = 50
	cfg.Scoring.EntropyAbsThreshold = 3.5
	cfg.Scoring.FreqQPSThreshold = 1000 // disable frequency signal in most tests
	cfg.Baseline.MinSamples = 100000    // rely on absolute thresholds for determinism
	cfg.Cooldown.Duration = time.Minute
	cfg.Ingest.ShardCount = 4
	cfg.Ingest.QueueSize = 16
	return cfg
}

func tunnelEvent(r *rand.Rand, ts time.Time, client, parent string) model.Event {
	return model.Event{
		TS:       ts,
		ClientIP: client,
		QName:    randomName(r, 58, parent),
		QType:    "A",
		RCode:    "NXDOMAIN",
	}
}

func benignEvent(ts time.Time, client, name string) model.Event {
	return model.Event{TS: ts, ClientIP: client, QName: name, RCode: "NOERROR", AnsCount: 1}
}

// feedSustained pushes one suspicious query in each of n consecutive buckets.
func feedSustained(e *Engine, r *rand.Rand, t0 time.Time, client, parent string, n int) {
	for i := 0; i < n; i++ {
		e.Ingest(tunnelEvent(r, t0.Add(time.Duration(i)*10*time.Second), client, parent))
	}
}

func TestSustainedTunnelFiresIsolatedDoesNot(t *testing.T) {
	var mu sync.Mutex
	var got []model.Alert
	e := New(testConfig(), nil, func(a model.Alert) { mu.Lock(); got = append(got, a); mu.Unlock() })
	r := rand.New(rand.NewSource(1))
	t0 := time.Unix(100000, 0)

	// one-off long random query: must NOT fire
	e.Ingest(tunnelEvent(r, t0, "c1", "evil.io"))
	if len(got) != 0 {
		t.Fatalf("isolated anomaly fired: %+v", got)
	}

	// sustained across 3 buckets: fires once
	feedSustained(e, r, t0.Add(time.Minute), "c1", "evil.io", 3)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 alert, got %d: %+v", len(got), got)
	}
	if got[0].TunnelKey != "evil.io" || got[0].Severity < model.SeverityLow {
		t.Fatalf("bad alert: %+v", got[0])
	}
}

func TestCooldownSuppressesStorm(t *testing.T) {
	var got []model.Alert
	var mu sync.Mutex
	e := New(testConfig(), nil, func(a model.Alert) { mu.Lock(); got = append(got, a); mu.Unlock() })
	r := rand.New(rand.NewSource(2))
	t0 := time.Unix(200000, 0)
	// keep tunneling continuously for 50s (5 buckets), well inside cooldown
	for i := 0; i < 25; i++ {
		e.Ingest(tunnelEvent(r, t0.Add(time.Duration(i)*2*time.Second), "c1", "evil.io"))
	}
	if len(got) != 1 {
		t.Fatalf("storm inside cooldown produced %d alerts, want 1", len(got))
	}
}

func TestWhitelistExempts(t *testing.T) {
	cfg := testConfig()
	cfg.Whitelist.Suffixes = []string{"batch.internal"}
	cfg.Whitelist.Regexps = []string{`^hb-[0-9]+\.heartbeat\.internal$`}
	var got []model.Alert
	e := New(cfg, nil, func(a model.Alert) { got = append(got, a) })
	r := rand.New(rand.NewSource(3))
	t0 := time.Unix(300000, 0)
	// legal long names on whitelisted batch domain: must not alert
	for i := 0; i < 6; i++ {
		e.Ingest(tunnelEvent(r, t0.Add(time.Duration(i)*10*time.Second), "c1", "batch.internal"))
	}
	// heartbeat names matching regexp
	for i := 0; i < 6; i++ {
		e.Ingest(model.Event{TS: t0.Add(time.Duration(i) * 10 * time.Second), ClientIP: "c1",
			QName: "hb-42.heartbeat.internal", RCode: "NXDOMAIN"})
	}
	if len(got) != 0 {
		t.Fatalf("whitelist should suppress all alerts, got %d: %+v", len(got), got)
	}
}

func TestOutOfOrderDoesNotCorrupt(t *testing.T) {
	var got []model.Alert
	var mu sync.Mutex
	e := New(testConfig(), nil, func(a model.Alert) { mu.Lock(); got = append(got, a); mu.Unlock() })
	r := rand.New(rand.NewSource(4))
	t0 := time.Unix(400000, 0)
	evs := make([]model.Event, 0, 4)
	for i := 0; i < 4; i++ {
		evs = append(evs, tunnelEvent(r, t0.Add(time.Duration(i)*10*time.Second), "c1", "evil.io"))
	}
	// shuffle arrival order
	r.Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
	for _, ev := range evs {
		e.Ingest(ev)
	}
	if len(got) != 1 {
		t.Fatalf("out-of-order sustained tunnel must fire exactly once, got %d", len(got))
	}
}

func TestLateBeyondGraceDropped(t *testing.T) {
	e := New(testConfig(), nil, nil)
	r := rand.New(rand.NewSource(5))
	t0 := time.Unix(500000, 0)
	e.Ingest(tunnelEvent(r, t0.Add(60*time.Second), "c1", "evil.io"))
	// far-late event: window size(60s)+grace(20s)=80s behind watermark -> drop
	alerts := e.Ingest(tunnelEvent(r, t0, "c1", "evil.io"))
	if len(alerts) != 0 {
		t.Fatalf("expired late event must be ignored, got %+v", alerts)
	}
}

func TestRecoveryNoDuplicateAndNoGap(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Persistence.Dir = dir

	t0 := time.Unix(600000, 0)
	r := rand.New(rand.NewSource(6))

	// --- run 1: accumulate two buckets but do NOT reach fire threshold ---
	var firstRun []model.Alert
	e1 := New(cfg, nil, func(a model.Alert) { firstRun = append(firstRun, a) })
	st, err := persist.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	e1.store = st
	for i := 0; i < 2; i++ {
		if err := e1.Submit(tunnelEvent(r, t0.Add(time.Duration(i)*10*time.Second), "c1", "evil.io")); err != nil {
			t.Fatal(err)
		}
	}
	if len(firstRun) != 0 {
		t.Fatal("pre-threshold phase must not alert")
	}
	if err := e1.Close(); err != nil { // snapshot seq=2, WAL prefix trimmed
		t.Fatal(err)
	}

	// simulate an event durably WAL-logged immediately before a crash but
	// never applied nor snapshotted
	stLate, err := persist.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	crashEvent := tunnelEvent(r, t0.Add(20*time.Second), "c1", "evil.io")
	if err := stLate.WALEntry(crashEvent); err != nil {
		t.Fatal(err)
	}
	stLate.Close()

	recover := func() []model.Alert {
		var got []model.Alert
		e := New(cfg, nil, func(a model.Alert) { got = append(got, a) })
		s2, err := persist.NewFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		e.store = s2
		if err := e.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		// snapshot (2 pre-crash buckets) + WAL replay (1 post-crash event)
		return got
	}

	runA := recover()
	if len(runA) != 1 {
		t.Fatalf("cross-restart sustained anomaly must fire once, got %d", len(runA))
	}
	// a brand-new process recovering the same files must produce the SAME
	// stable alert id -> never double-fires across crashes
	runB := recover()
	if len(runB) != 1 || runB[0].ID != runA[0].ID {
		t.Fatalf("replay must be idempotent: A=%+v B=%+v", runA, runB)
	}
}

func TestConcurrentIngestAndBackpressure(t *testing.T) {
	cfg := testConfig()
	cfg.Ingest.ShardCount = 8
	cfg.Ingest.QueueSize = 4
	e := New(cfg, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(700000, 0)
	submit := func(ev model.Event) {
		for {
			if err := e.Submit(ev); err == nil {
				return
			} else if err != ErrQueueFull {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(g + 100)))
			for i := 0; i < 200; i++ {
				submit(benignEvent(t0.Add(time.Duration(i)*time.Millisecond), "c-benign-"+string(rune('a'+g%4)), "api.corp"))
				submit(tunnelEvent(r, t0.Add(time.Duration(i)*time.Second), "c-evil-"+string(rune('a'+g%4)), "evil.io"))
			}
		}(g)
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e.Watermark().Equal(t0.Add(199 * time.Second)) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("watermark did not advance under concurrent load: %v", e.Watermark())
}

func TestMultiFeatureRequired(t *testing.T) {
	// Only frequency high (with many short benign names) should not by itself
	// trip a tunnel alert when frequency is enabled and names are normal.
	cfg := testConfig()
	cfg.Scoring.FreqQPSThreshold = 5
	cfg.Baseline.HeartbeatMaxQPS = 1
	var got []model.Alert
	e := New(cfg, nil, func(a model.Alert) { got = append(got, a) })
	t0 := time.Unix(800000, 0)
	for i := 0; i < 30; i++ {
		e.Ingest(model.Event{TS: t0.Add(time.Duration(i) * 100 * time.Millisecond),
			ClientIP: "c1", QName: "short.io", RCode: "NOERROR", AnsCount: 2})
	}
	if len(got) != 0 {
		t.Fatalf("benign high-rate short names must not alert on one signal: %+v", got)
	}
}
