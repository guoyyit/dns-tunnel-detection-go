// Package model defines the core data types shared across the detector.
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

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "none"
	}
}

// DNSResponse carries optional response-side features for a query.
// Zero values mean "no response observed".
type DNSResponse struct {
	Observed    bool
	IPCount     int
	AnswerBytes int
	TTL         int
	NXDOMAIN    bool
	RCode       int
}

// Event is a single timestamped DNS query event.
// Events may arrive out of order and late.
type Event struct {
	Time     time.Time
	ClientIP string
	Name     string
	QType    uint16
	Response *DNSResponse
}

// FeatureKey identifies a tunnel characteristic that drove an alert.
type FeatureKey string

// Alert is a deduplicated, cooldown-managed alert record.
type Alert struct {
	ID         string
	ClientIP   string
	Name       string
	Feature    FeatureKey
	Severity   Severity
	Score      float64
	WindowFrom time.Time
	WindowTo   time.Time
	OpenedAt   time.Time
	Message    string
}

// AlertUpdate describes an alert lifecycle event delivered to sinks.
type AlertUpdateKind int

const (
	AlertRaised AlertUpdateKind = iota
	AlertSeverityChanged
	AlertRepeatedSuppressed
	AlertReopened
)

type AlertUpdate struct {
	Kind     AlertUpdateKind
	Alert    Alert
	Previous Severity
	At       time.Time
}
