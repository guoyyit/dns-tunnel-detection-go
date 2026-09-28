package persist

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

func mkEvent(i int) model.Event {
	return model.Event{
		TS:       time.Unix(int64(1000+i), 0),
		ClientIP: "c1",
		QName:    "a.example",
	}
}

func TestWALSnapshotReplay(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs := st.(*FileStore)
	for i := 0; i < 5; i++ {
		if err := fs.WALEntry(mkEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	if fs.LastSeq() != 5 {
		t.Fatalf("seq=%d want 5", fs.LastSeq())
	}

	states := []State{{Shard: 0, Watermark: 1004, Baseline: json.RawMessage(`{}`)}}
	if err := fs.SaveSnapshot(states); err != nil {
		t.Fatal(err)
	}
	// events after snapshot
	if err := fs.WALEntry(mkEvent(5)); err != nil {
		t.Fatal(err)
	}

	got, err := fs.LoadSnapshot()
	if err != nil || len(got) != 1 || got[0].Watermark != 1004 {
		t.Fatalf("snapshot load: %v %+v", err, got)
	}
	seq, err := fs.SnapshotSeq()
	if err != nil || seq != 5 {
		t.Fatalf("snapshot seq=%d err=%v", seq, err)
	}
	var replayed []int64
	err = fs.ReplayWAL(context.Background(), seq, func(e model.Event) error {
		replayed = append(replayed, e.TS.Unix())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 1 || replayed[0] != 1005 {
		t.Fatalf("replayed=%v", replayed)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	// reopen: seq must continue beyond old entries, replay still consistent
	st2, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs2 := st2.(*FileStore)
	if fs2.LastSeq() != 6 {
		t.Fatalf("reopened seq=%d want 6", fs2.LastSeq())
	}
	count := 0
	fs2.ReplayWAL(context.Background(), seq, func(e model.Event) error { count++; return nil })
	if count != 1 {
		t.Fatalf("after trim replay count=%d want 1", count)
	}
}

func TestEmptyDirDisabled(t *testing.T) {
	s, err := NewFileStore("")
	if err != nil || s != nil {
		t.Fatalf("empty dir must disable store: %v %v", s, err)
	}
}

func TestTornTrailingLineTolerated(t *testing.T) {
	dir := t.TempDir()
	good, _ := json.Marshal(walRecord{Type: "event", Seq: 1, Event: &model.Event{QName: "x"}})
	good = append(good, '\n')
	if err := os.WriteFile(filepath.Join(dir, walName), append(good, []byte(`{"type":"event","seq":2,"ev`)...), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs := st.(*FileStore)
	if fs.LastSeq() != 1 {
		t.Fatalf("torn line must be ignored, seq=%d", fs.LastSeq())
	}
}

func TestSnapshotGC(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewFileStore(dir)
	fs := st.(*FileStore)
	for i := 0; i < 4; i++ {
		fs.WALEntry(mkEvent(i))
		if err := fs.SaveSnapshot([]State{{Shard: 0}}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "snapshot-") {
			n++
		}
	}
	if n > 2 {
		t.Fatalf("expected at most 2 retained snapshots, got %d", n)
	}
}
