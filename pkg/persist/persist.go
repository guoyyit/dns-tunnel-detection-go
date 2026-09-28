// Package persist provides crash-safe state persistence and recovery:
// window accumulations and fired-alert states are periodically snapshotted
// to a file (write-temp + fsync + atomic rename), so a restart neither
// double-fires nor loses sustained anomalies spanning the restart.
package persist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/pkg/model"
)

// CurrentVersion is the snapshot format version.
const CurrentVersion = 1

// BucketDTO is a serializable window bucket.
type BucketDTO struct {
	Index int64              `json:"index"`
	Start time.Time          `json:"start"`
	Count int64              `json:"count"`
	Max   map[string]float64 `json:"max,omitempty"`
	Sum   map[string]float64 `json:"sum,omitempty"`
	Raw   map[string]float64 `json:"raw,omitempty"`
}

// WindowDTO is a serializable sliding window.
type WindowDTO struct {
	ClientIP string      `json:"client_ip"`
	Name     string      `json:"name"`
	CfgGen   int64       `json:"cfg_gen"`
	Buckets  []BucketDTO `json:"buckets"`
	Lowest   int64       `json:"lowest"`
	Highest  int64       `json:"highest"`
}

// AlertDTO is a serializable alert state.
type AlertDTO struct {
	Alert         model.Alert `json:"alert"`
	FirstSeen     time.Time   `json:"first_seen"`
	LastFiredAt   time.Time   `json:"last_fired_at"`
	LastEvaluated time.Time   `json:"last_evaluated"`
	FiredCount    int         `json:"fired_count"`
	Suppressed    int         `json:"suppressed"`
	CooldownUntil time.Time   `json:"cooldown_until"`
	Active        bool        `json:"active"`
}

// Snapshot is the full persisted state.
type Snapshot struct {
	SavedAt time.Time   `json:"saved_at"`
	Version int         `json:"version"`
	Windows []WindowDTO `json:"windows"`
	Alerts  []AlertDTO  `json:"alerts"`
}

// NewEmpty returns an empty current-version snapshot.
func NewEmpty() *Snapshot {
	return &Snapshot{Version: CurrentVersion, Windows: []WindowDTO{}, Alerts: []AlertDTO{}}
}

// Save atomically writes s to path: marshal once, write a temp file in
// the same directory, fsync it, then rename over the target. A crash
// leaves either the old file or the complete new one.
func Save(path string, s *Snapshot) error {
	if path == "" {
		return errors.New("persist: empty path")
	}
	if s == nil {
		s = NewEmpty()
	}
	s.Version = CurrentVersion
	if s.SavedAt.IsZero() {
		s.SavedAt = time.Now().UTC()
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".snap-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	// Best-effort directory fsync so the rename is durable.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Load reads a snapshot from path. A missing file yields an empty
// snapshot and no error (fresh start).
func Load(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewEmpty(), nil
		}
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	if s.Version > CurrentVersion {
		return nil, fmt.Errorf("persist: snapshot version %d newer than supported %d", s.Version, CurrentVersion)
	}
	if s.Windows == nil {
		s.Windows = []WindowDTO{}
	}
	if s.Alerts == nil {
		s.Alerts = []AlertDTO{}
	}
	return s, nil
}
