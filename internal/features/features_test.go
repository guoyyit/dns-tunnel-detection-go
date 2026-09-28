package features

import (
	"testing"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

func TestShannonEntropy(t *testing.T) {
	if got := ShannonEntropy("aaaa"); got != 0 {
		t.Errorf("constant string entropy=%v want 0", got)
	}
	if got := ShannonEntropy("ab"); got <= 0.99 || got >= 1.01 {
		t.Errorf("binary entropy=%v want ~1", got)
	}
	if got := ShannonEntropy(""); got != 0 {
		t.Errorf("empty entropy=%v want 0", got)
	}
}

func TestExtract(t *testing.T) {
	e := &model.Event{QName: "A1B2.Example.COM.", RCode: "NXDOMAIN"}
	f := Extract(e)
	if f.NameLen != len("a1b2.example.com") {
		t.Errorf("name not normalized: len=%d", f.NameLen)
	}
	if f.LabelCount != 3 {
		t.Errorf("labels=%d want 3", f.LabelCount)
	}
	if f.LongestLabel != 7 {
		t.Errorf("longest=%d want 7", f.LongestLabel)
	}
	if !f.NXDomain || !f.HasResponse {
		t.Errorf("response flags wrong: %+v", f)
	}
	if f.DigitRatio <= 0 {
		t.Errorf("digit ratio=%v want >0", f.DigitRatio)
	}
}
