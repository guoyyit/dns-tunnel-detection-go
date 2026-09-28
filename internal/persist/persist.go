// Package persist provides write-ahead logging and snapshots so that
// window and alert state survives process restarts.
//
// Recovery contract:
//
//   - Every accepted event is first durably appended to a WAL record.
//   - Periodically the full per-shard state is written to an atomic
//     snapshot tagged with the WAL sequence it includes.
//   - On startup the newest snapshot is loaded and only WAL events with a
//     higher sequence are replayed through the deterministic engine.
//
// Because all window/alert decisions are pure functions of the event
// sequence (event timestamps drive time), replay reproduces the exact
// pre-crash state: already-fired alerts keep the same stable ids (no
// duplicates) and evidence accumulated across the restart is preserved
// (no missed sustained anomalies).
package persist

import (
	"context"
	"encoding/json"
	"io"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

// State bundles one shard's engine state that must survive a restart.
type State struct {
	Watermark int64           `json:"watermark_unixnano"`
	Baseline  json.RawMessage `json:"baseline,omitempty"`
	Window    json.RawMessage `json:"window,omitempty"`
	Alerting  json.RawMessage `json:"alerting,omitempty"`
	Shard     int             `json:"shard"`
}

// Store persists events (WAL) and periodic snapshots.
type Store interface {
	// WALEntry durably appends an event before it is applied.
	WALEntry(e model.Event) error
	// SaveSnapshot atomically writes a full per-shard state snapshot.
	SaveSnapshot(states []State) error
	// LoadSnapshot reads the newest snapshot, if any.
	LoadSnapshot() ([]State, error)
	// SnapshotSeq returns the WAL sequence of the newest snapshot.
	SnapshotSeq() (int64, error)
	// ReplayWAL streams events recorded after the snapshot seq.
	ReplayWAL(ctx context.Context, sinceSeq int64, fn func(model.Event) error) error
	// TrimWAL discards WAL entries covered by the newest snapshot.
	TrimWAL(snapshotUnixNano int64) error
	io.Closer
}
