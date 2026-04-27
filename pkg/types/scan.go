package types

import (
	"time"
)

// ScanPhase represents the current phase of an active scan.
type ScanPhase string

const (
	PhaseRECON        ScanPhase = "RECON"
	PhaseANALYSIS     ScanPhase = "ANALYSIS"
	PhaseEXPLOITATION ScanPhase = "EXPLOITATION"
	PhaseREPORTING    ScanPhase = "REPORTING"
)

func (p ScanPhase) Valid() bool {
	switch p {
	case PhaseRECON, PhaseANALYSIS, PhaseEXPLOITATION, PhaseREPORTING:
		return true
	}
	return false
}

func (p ScanPhase) String() string {
	return string(p)
}

// ScanStatus represents the lifecycle state of a scan.
type ScanStatus string

const (
	StatusPENDING   ScanStatus = "PENDING"
	StatusRUNNING   ScanStatus = "RUNNING"
	StatusPAUSED    ScanStatus = "PAUSED"
	StatusCOMPLETED ScanStatus = "COMPLETED"
	StatusFAILED    ScanStatus = "FAILED"
)

func (s ScanStatus) Valid() bool {
	switch s {
	case StatusPENDING, StatusRUNNING, StatusPAUSED, StatusCOMPLETED, StatusFAILED:
		return true
	}
	return false
}

func (s ScanStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status is a terminal state.
func (s ScanStatus) IsTerminal() bool {
	return s == StatusCOMPLETED || s == StatusFAILED
}

// LLMTier represents the capability tier for LLM routing.
type LLMTier string

const (
	TierLocal        LLMTier = "LOCAL"
	TierCloudCheap   LLMTier = "CLOUD_CHEAP"
	TierCloudStrong  LLMTier = "CLOUD_STRONG"
	TierUncensored   LLMTier = "UNCENSORED"
	TierAbliterated  LLMTier = "ABLITERATED"
)

func (t LLMTier) Valid() bool {
	switch t {
	case TierLocal, TierCloudCheap, TierCloudStrong, TierUncensored, TierAbliterated:
		return true
	}
	return false
}

func (t LLMTier) String() string {
	return string(t)
}

// Scan represents a full offensive scan operation.
type Scan struct {
	ID          string     `json:"id" gorm:"primaryKey"`
	TargetURL   string     `json:"target_url"`
	Phase       ScanPhase  `json:"phase"`
	Status      ScanStatus `json:"status"`
	Notes       string     `json:"notes,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Target represents a discovered target host with its metadata.
type Target struct {
	ID         string   `json:"id" gorm:"primaryKey"`
	Host       string   `json:"host"`
	Ports      []Port   `json:"ports"`
	Services   []string `json:"services"`
	TechStack  []string `json:"tech_stack"`
	Findings   []string `json:"finding_ids,omitempty"`
	ScanID     string   `json:"scan_id"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Port represents an open port with protocol and service info.
type Port struct {
	Number  int    `json:"number"`
	Proto   string `json:"protocol"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	State   string `json:"state"`
}

// Finding represents a security finding or vulnerability.
type Finding struct {
	ID                  string   `json:"id" gorm:"primaryKey"`
	Type                string   `json:"type"`
	Severity            string   `json:"severity"` // critical, high, medium, low, info
	Description         string   `json:"description"`
	Evidence            string   `json:"evidence"`
	ReproductionSteps   string   `json:"reproduction_steps"`
	ScanID              string   `json:"scan_id"`
	TargetID            string   `json:"target_id,omitempty"`
	CVE                 string   `json:"cve,omitempty"`
	CWE                 string   `json:"cwe,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

// VulnChain represents a chained vulnerability path.
type VulnChain struct {
	ID         string   `json:"id" gorm:"primaryKey"`
	Steps      []string `json:"steps"`
	Impact     string   `json:"impact"`
	FindingIDs []string `json:"finding_ids"`
	ScanID     string   `json:"scan_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateScanRequest is the input for creating a new scan.
type CreateScanRequest struct {
	TargetURL string   `json:"target_url" binding:"required"`
	Phase     ScanPhase `json:"phase,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// PauseScanRequest pauses or resumes a scan.
type PauseScanRequest struct {
	Resume bool `json:"resume,omitempty"`
}
