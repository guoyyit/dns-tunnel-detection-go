package persist

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

func TestLoadMissingIsEmpty(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != CurrentVersion || len(s.Windows) != 0 || len(s.Alerts) != 0 {
		t.Fatalf("missing file must yield empty current snapshot: %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := NewEmpty()
	s.Windows = []WindowDTO{{
		ClientIP: "1.1.1.1", Name: "evil.test", CfgGen: 3, Lowest: 5, Highest: 9,
		Buckets: []BucketDTO{{Index: 5, Start: time.Now().UTC(), Count: 7,
			Max: map[string]float64{"x": 1.2}, Sum: map[string]float64{"x": 3.4},
			Raw: map[string]float64{"x": 1}}},
	}}
	s.Alerts = []AlertDTO{{
		Alert: model.Alert{ID: "id1", ClientIP: "1.1.1.1", Name: "evil.test",
			Feature: "tunnel", Severity: model.SeverityHigh, Score: 4},
		FiredCount: 2, CooldownUntil: time.Now().Add(time.Hour).UTC(), Active: true,
	}}
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Windows) != 1 || got.Windows[0].CfgGen != 3 || got.Windows[0].Lowest != 5 {
		t.Fatalf("windows not restored: %+v", got.Windows)
	}
	if got.Windows[0].Buckets[0].Raw["x"] != 1 {
		t.Fatal("raw bucket scores must persist")
	}
	if len(got.Alerts) != 1 || got.Alerts[0].FiredCount != 2 || !got.Alerts[0].Active {
		t.Fatalf("alerts not restored: %+v", got.Alerts)
	}
}

func TestSaveAtomicLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := Save(path, NewEmpty()); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file leaked: %s", e.Name())
		}
	}
}

func TestEmptyPathErrors(t *testing.T) {
	if err := Save("", NewEmpty()); err == nil {
		t.Fatal("empty path must error")
	}
}

func TestCorruptFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("corrupt snapshot must return an error")
	}
}
