// Command dtsd is a local DNS-tunnel detection demo. It ingests events
// from an in-memory channel (no network listener, no credentials),
// prints alert updates and periodically persists state.
package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/config"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/detector"
	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Default()
	// Put the snapshot in a temp dir; persistence is crash-safe there.
	tmp, err := os.MkdirTemp("", "dtsd-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)
	cfg.PersistPath = filepath.Join(tmp, "state.json")

	// Legit heartbeat domain is exempt from alerting.
	cfg.Exemptions = []config.Rule{
		{Name: "known heartbeat", NameSuffix: "heartbeat.internal"},
	}
	// Fully trusted zone is whitelisted.
	cfg.Whitelist = []config.Rule{
		{Name: "corp zone", NameSuffix: "example.com"},
	}

	out := make(chan model.AlertUpdate, 128)
	d := detector.New(cfg, 4, out)

	// Deterministic virtual clock drives both generation and ticks.
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	clock := now
	d.SetClock(func() time.Time { return clock })

	d.Start(ctx)
	defer func() { _ = d.Close() }()

	// Alert printer.
	go func() {
		for u := range out {
			if u.Kind == model.AlertRepeatedSuppressed {
				continue
			}
			fmt.Printf("[ALERT] kind=%s %s client=%s zone=%s sev=%s score=%.2f\n",
				kindName(u.Kind), u.At.Format(time.RFC3339), u.Alert.ClientIP,
				u.Alert.Name, u.Alert.Severity, u.Alert.Score)
		}
	}()

	// Producer on an in-memory channel: mix normal, heartbeat,
	// whitelisted and tunnelling-looking traffic.
	events := make(chan model.Event, 256)
	go func() {
		rng := rand.New(rand.NewSource(1))
		const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
		for i := 0; i < 4000; i++ {
			t := now.Add(time.Duration(i) * 250 * time.Millisecond)
			var e model.Event
			switch i % 10 {
			case 0, 1: // legit short names
				e = model.Event{Time: t, ClientIP: "10.0.0.1",
					Name:     []string{"mail.example.com", "news.example.com", "api.example.com"}[i%3],
					Response: &model.DNSResponse{Observed: true, IPCount: 2, AnswerBytes: 120, TTL: 60}}
			case 2: // whitelisted long names (must never alert)
				e = model.Event{Time: t, ClientIP: "10.0.0.1",
					Name:     randLong(rng, alphabet) + ".host.corp.example.com",
					Response: &model.DNSResponse{Observed: true, IPCount: 1, AnswerBytes: 88}}
			case 3: // known heartbeat (exempt)
				e = model.Event{Time: t, ClientIP: "10.0.0.2",
					Name:     "hb.heartbeat.internal",
					Response: &model.DNSResponse{Observed: true, IPCount: 1, AnswerBytes: 40}}
			default: // tunnel-like: long high-entropy labels, tiny/NXDOMAIN answers
				e = model.Event{Time: t, ClientIP: "10.0.0.9",
					Name:     randLong(rng, alphabet) + ".tun.evil.test",
					Response: &model.DNSResponse{Observed: true, IPCount: 0, NXDOMAIN: true, AnswerBytes: 16}}
			}
			events <- e
		}
		close(events)
	}()

	// Pump events and advance the virtual clock in lockstep.
	for e := range events {
		d.Ingest(e)
		if nxt := e.Time; nxt.After(clock) {
			clock = nxt
			d.AdvanceTest(clock)
		}
	}
	// Final window flush well past the last event.
	clock = clock.Add(10 * time.Minute)
	d.AdvanceTest(clock)
	time.Sleep(100 * time.Millisecond)

	st := d.Stats()
	fmt.Printf("[STATS] ingested=%d whitelisted=%d late=%d raised=%d suppressed=%d reopened=%d escalated=%d\n",
		st.Ingested, st.Whitelisted, st.RejectedLate, st.AlertsRaised,
		st.AlertsSuppressed, st.AlertsReopened, st.AlertsEscalated)
	fmt.Println("[STATE] persisted at", cfg.PersistPath)
}

func kindName(k model.AlertUpdateKind) string {
	switch k {
	case model.AlertRaised:
		return "raised"
	case model.AlertSeverityChanged:
		return "severity-changed"
	case model.AlertReopened:
		return "reopened"
	default:
		return "suppressed"
	}
}

func randLong(rng *rand.Rand, alphabet string) string {
	b := make([]byte, 60)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}
