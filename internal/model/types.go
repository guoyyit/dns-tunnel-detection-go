// Package model defines the core event and alert data types for the
// DNS tunnel detection service.
package model

import "time"

// Severity of an alert.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string { return severityNames[s] }

var severityNames = [...]string{"none", "low", "medium", "high", "critical"}

// Event is a single timestamped DNS query observation.
//
// Events may arrive out of order or late. All time-based logic inside the
// engine uses Event.TS (never the wall clock), which makes evaluation
// deterministic and reproducible.
type Event struct {
	TS       time.Time `json:"ts"`
	ClientIP string    `json:"client_ip"`
	QName    string    `json:"qname"`
	QType    string    `json:"qtype,omitempty"`
	RCode    string    `json:"rcode,omitempty"`

	// Response characteristics (zero/empty when not observed).
	AnsCount          int   `json:"ans_count,omitempty"`
	RespLatencyMicros int64 `json:"resp_latency_micros,omitempty"`
}

// Feature is the extracted per-query feature vector.
type Feature struct {
	NameLen      int
	Entropy      float64
	LabelCount   int
	LongestLabel int
	DigitRatio   float64
	VowelRatio   float64
	HasResponse  bool
	AnsCount     int
	NXDomain     bool
	RespLatency  int64 // micros, 0 when unknown
}

// Alert is a deduplicated, cooldown-controlled tunnel alert.
type Alert struct {
	ID         string    `json:"id"`
	ClientIP   string    `json:"client_ip"`
	TunnelKey  string    `json:"tunnel_key"`
	Severity   Severity  `json:"severity"`
	Score      float64   `json:"score"`
	FirstTS    time.Time `json:"first_ts"`
	FireTS     time.Time `json:"fire_ts"`
	LastTS     time.Time `json:"last_ts"`
	Reasons    []string  `json:"reasons,omitempty"`
	SampleName string    `json:"sample_name,omitempty"`
}
