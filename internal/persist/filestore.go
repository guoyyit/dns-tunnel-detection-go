// This file implements the directory-backed Store.
//
// On-disk layout (created lazily inside Dir):
//
//	wal.log              newline-delimited JSON records (append only)
//	snapshot-<n>.tmp     temporary upload, renamed atomically to
//	snapshot-<n>.json    a completed snapshot
//
// WAL record types:
//
//	{"type":"event","seq":N,"event":{...}}
//
// A snapshot is always written together with the WAL sequence number it is
// based on. On recovery the newest snapshot is loaded and only WAL events
// with seq > snapshot seq are replayed. After a successful snapshot the
// older WAL prefix is discarded (rewrite), so disk usage stays bounded.
package persist

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

const (
	walName = "wal.log"
)

// FileStore is a fs-backed Store safe for concurrent use.
type FileStore struct {
	dir string

	mu      sync.Mutex
	f       *os.File
	enc     *json.Encoder
	seq     int64
	lastSeq int64 // seq covered by the last snapshot
	bytes   int64
}

type walRecord struct {
	Type  string       `json:"type"`
	Seq   int64        `json:"seq"`
	Event *model.Event `json:"event,omitempty"`
}

type snapshotFile struct {
	Seq    int64   `json:"seq"`
	States []State `json:"states"`
}

// NewFileStore creates/opens a directory-backed store.
// An empty dir yields (nil, nil) meaning persistence is disabled.
func NewFileStore(dir string) (Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	fs := &FileStore{dir: dir}
	if err := fs.openWAL(); err != nil {
		return nil, err
	}
	return fs, nil
}

func (s *FileStore) walPath() string { return filepath.Join(s.dir, walName) }

func (s *FileStore) openWAL() error {
	f, err := os.OpenFile(s.walPath(), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	s.f = f
	s.enc = json.NewEncoder(f)
	seq, _, err := s.scanWAL(func(walRecord) error { return nil })
	if err != nil {
		return err
	}
	if seq == 0 {
		// WAL was trimmed by a snapshot; continue from the snapshot seq so
		// that newly appended records stay globally monotonic.
		if sq, err := s.SnapshotSeq(); err == nil && sq > seq {
			seq = sq
		}
	}
	s.seq = seq
	return nil
}

// scanWAL iterates valid records, calling fn for each. It returns the
// highest sequence and the byte offset of the end of the valid prefix.
// A torn final line (crash mid-write) is tolerated and treated as EOF.
func (s *FileStore) scanWAL(fn func(walRecord) error) (int64, int64, error) {
	path := s.walPath()
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	var seq int64
	var offset int64
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var rec walRecord
			if jerr := json.Unmarshal(line, &rec); jerr == nil && rec.Type == "event" {
				if ferr := fn(rec); ferr != nil {
					return seq, offset, ferr
				}
				if rec.Seq > seq {
					seq = rec.Seq
				}
				offset += int64(len(line))
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return seq, offset, err
		}
	}
	return seq, offset, nil
}

// WALEntry appends an event to the WAL.
func (s *FileStore) WALEntry(e model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	rec := walRecord{Type: "event", Seq: s.seq, Event: &e}
	if err := s.enc.Encode(rec); err != nil {
		return err
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	s.bytes = 0 // recomputed lazily on trim; size tracked via stat when needed
	return nil
}

// SaveSnapshot atomically writes a full snapshot tagged with the current
// WAL sequence, then trims the WAL prefix it supersedes.
func (s *FileStore) SaveSnapshot(states []State) error {
	s.mu.Lock()
	seq := s.seq
	s.mu.Unlock()

	payload := snapshotFile{Seq: seq, States: states}
	tmp := filepath.Join(s.dir, fmt.Sprintf("snapshot-%d.tmp", seq))
	final := filepath.Join(s.dir, fmt.Sprintf("snapshot-%d.json", seq))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(payload); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	if err := s.trimTo(seq); err != nil {
		return err
	}
	s.mu.Lock()
	s.lastSeq = seq
	s.mu.Unlock()
	return s.gcSnapshots(final)
}

func (s *FileStore) trimTo(seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Rewrite WAL keeping only records with seq > snapshot seq.
	path := s.walPath()
	tmp := path + ".tmp"
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		in.Close()
		return err
	}
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var rec walRecord
			if json.Unmarshal(line, &rec) == nil && rec.Seq > seq {
				w.Write(line)
			}
		}
		if err != nil {
			break
		}
	}
	w.Flush()
	in.Close()
	out.Sync()
	out.Close()
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Reopen handle because the file was replaced; keep the monotonic seq.
	if s.f != nil {
		s.f.Close()
	}
	return s.openWALLocked(seq)
}

// noop keeps import set small

func (s *FileStore) openWALLocked(keepSeq int64) error {
	f, err := os.OpenFile(s.walPath(), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	s.f = f
	s.enc = json.NewEncoder(f)
	seq, _, serr := s.scanWAL(func(walRecord) error { return nil })
	if serr != nil {
		return serr
	}
	if seq == 0 {
		if sq, err := s.SnapshotSeq(); err == nil && sq > seq {
			seq = sq
		}
	}
	if seq > keepSeq {
		keepSeq = seq
	}
	s.seq = keepSeq
	return err
}

func (s *FileStore) gcSnapshots(keep string) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var snaps []string
	for _, en := range entries {
		n := en.Name()
		if strings.HasPrefix(n, "snapshot-") && strings.HasSuffix(n, ".json") {
			snaps = append(snaps, filepath.Join(s.dir, n))
		}
	}
	sort.Strings(snaps)
	if len(snaps) <= 2 {
		return nil
	}
	for _, old := range snaps[:len(snaps)-2] {
		if old != keep {
			os.Remove(old)
		}
	}
	return nil
}

// LoadSnapshot reads the newest snapshot.
func (s *FileStore) LoadSnapshot() ([]State, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var snaps []string
	for _, en := range entries {
		n := en.Name()
		if strings.HasPrefix(n, "snapshot-") && strings.HasSuffix(n, ".json") {
			snaps = append(snaps, filepath.Join(s.dir, n))
		}
	}
	if len(snaps) == 0 {
		return nil, nil
	}
	sort.Strings(snaps)
	data, err := os.ReadFile(snaps[len(snaps)-1])
	if err != nil {
		return nil, err
	}
	var sf snapshotFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.lastSeq = sf.Seq
	s.mu.Unlock()
	return sf.States, nil
}

// SnapshotSeq returns the seq associated with the newest snapshot or 0.
func (s *FileStore) SnapshotSeq() (int64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	var snaps []string
	for _, en := range entries {
		n := en.Name()
		if strings.HasPrefix(n, "snapshot-") && strings.HasSuffix(n, ".json") {
			snaps = append(snaps, n)
		}
	}
	if len(snaps) == 0 {
		return 0, nil
	}
	sort.Strings(snaps)
	var seq int64
	if _, err := fmt.Sscanf(filepath.Base(snaps[len(snaps)-1]), "snapshot-%d.json", &seq); err != nil {
		return 0, err
	}
	return seq, nil
}

// ReplayWAL streams events recorded after the snapshot.
func (s *FileStore) ReplayWAL(ctx context.Context, since int64, fn func(model.Event) error) error {
	_, _, err := s.scanWAL(func(rec walRecord) error {
		if rec.Seq <= since || rec.Event == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return fn(*rec.Event)
	})
	return err
}

// TrimWAL discards entries at or before the snapshot timestamp; here seq is
// used as the snapshot high-water mark.
func (s *FileStore) TrimWAL(snapshotUnixNano int64) error {
	seq, err := s.SnapshotSeq()
	if err != nil {
		return err
	}
	if seq > 0 {
		return s.trimTo(seq)
	}
	return nil
}

// LastSeq returns the current WAL sequence (for tests).
func (s *FileStore) LastSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// Close flushes and closes the WAL file.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		err := s.f.Sync()
		if err2 := s.f.Close(); err == nil {
			err = err2
		}
		s.f = nil
		return err
	}
	return nil
}
