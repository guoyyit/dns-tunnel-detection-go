// Package features extracts per-query anomaly features.
package features

import (
	"math"
	"strings"

	"github.com/guoyyit/dns-tunnel-detection-go/internal/model"
)

// Extract computes the feature vector for a single DNS event.
//
// The query name is lower-cased and stripped of a single trailing dot so
// that the same logical name always yields identical features regardless
// of presentation.
func Extract(e *model.Event) model.Feature {
	name := strings.ToLower(strings.TrimSuffix(e.QName, "."))

	f := model.Feature{
		NameLen:     len(name),
		Entropy:     ShannonEntropy(name),
		HasResponse: e.AnsCount > 0 || e.RespLatencyMicros > 0 || e.RCode != "",
		AnsCount:    e.AnsCount,
		NXDomain:    strings.EqualFold(e.RCode, "NXDOMAIN"),
		RespLatency: e.RespLatencyMicros,
	}

	var digits, vowels, letters int
	for _, r := range name {
		switch {
		case r >= '0' && r <= '9':
			digits++
			letters++
		case r == 'a' || r == 'e' || r == 'i' || r == 'o' || r == 'u':
			vowels++
			letters++
		case r >= 'a' && r <= 'z':
			letters++
		}
	}
	if letters > 0 {
		f.DigitRatio = float64(digits) / float64(letters)
		f.VowelRatio = float64(vowels) / float64(letters)
	}

	longest := 0
	for _, label := range strings.Split(name, ".") {
		f.LabelCount++
		if len(label) > longest {
			longest = len(label)
		}
	}
	f.LongestLabel = longest
	return f
}

// ShannonEntropy returns the Shannon entropy (bits per byte) of s.
// Dots are included as characters. The empty string has entropy 0.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
