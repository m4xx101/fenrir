package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/m4xx101/shannon/pkg/types"
)

// SQLiteStore implements ScanStore backed by SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite-backed store.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite is not truly concurrent for writes
	db.SetMaxIdleConns(1)

	store := &SQLiteStore{db: db}
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing schema: %w", err)
	}

	return store, nil
}

func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target_url TEXT NOT NULL,
		phase TEXT NOT NULL DEFAULT 'RECON',
		status TEXT NOT NULL DEFAULT 'PENDING',
		notes TEXT DEFAULT '',
		created_at TEXT NOT NULL,
		completed_at TEXT,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		host TEXT NOT NULL,
		ports TEXT NOT NULL DEFAULT '[]',
		services TEXT NOT NULL DEFAULT '[]',
		tech_stack TEXT NOT NULL DEFAULT '[]',
		finding_ids TEXT NOT NULL DEFAULT '[]',
		scan_id TEXT NOT NULL,
		discovered_at TEXT NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		description TEXT NOT NULL,
		evidence TEXT NOT NULL DEFAULT '',
		reproduction_steps TEXT NOT NULL DEFAULT '',
		scan_id TEXT NOT NULL,
		target_id TEXT DEFAULT '',
		cve TEXT DEFAULT '',
		cwe TEXT DEFAULT '',
		tags TEXT NOT NULL DEFAULT '[]',
		created_at TEXT NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS vuln_chains (
		id TEXT PRIMARY KEY,
		steps TEXT NOT NULL DEFAULT '[]',
		impact TEXT NOT NULL,
		finding_ids TEXT NOT NULL DEFAULT '[]',
		scan_id TEXT NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	CREATE INDEX IF NOT EXISTS idx_scans_phase ON scans(phase);
	CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_targets_scan ON targets(scan_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close releases the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) CreateScan(scan *types.Scan) error {
	_, err := s.db.Exec(
		`INSERT INTO scans (id, target_url, phase, status, notes, created_at, completed_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scan.ID, scan.TargetURL, scan.Phase, scan.Status, scan.Notes,
		scan.CreatedAt.Format(time.RFC3339), ptrTime(scan.CompletedAt),
		scan.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) GetScan(id string) (*types.Scan, error) {
	row := s.db.QueryRow(
		`SELECT id, target_url, phase, status, notes, created_at, completed_at, updated_at FROM scans WHERE id = ?`,
		id,
	)

	var scan types.Scan
	var completedAt sql.NullString
	if err := row.Scan(&scan.ID, &scan.TargetURL, &scan.Phase, &scan.Status, &scan.Notes,
		&scan.CreatedAt, &completedAt, &scan.UpdatedAt); err != nil {
		return nil, err
	}

	if completedAt.Valid {
		t, _ := time.Parse(time.RFC3339, completedAt.String)
		scan.CompletedAt = &t
	}

	return &scan, nil
}

func (s *SQLiteStore) GetScans(limit, offset int) ([]types.Scan, error) {
	rows, err := s.db.Query(
		`SELECT id, target_url, phase, status, notes, created_at, completed_at, updated_at FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []types.Scan
	for rows.Next() {
		var scan types.Scan
		var completedAt sql.NullString
		if err := rows.Scan(&scan.ID, &scan.TargetURL, &scan.Phase, &scan.Status, &scan.Notes,
			&scan.CreatedAt, &completedAt, &scan.UpdatedAt); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, completedAt.String)
			scan.CompletedAt = &t
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

func (s *SQLiteStore) UpdateScan(scan *types.Scan) error {
	scan.UpdatedAt = time.Now().UTC()
	var completedAt sql.NullString
	if scan.CompletedAt != nil {
		completedAt.Valid = true
		completedAt.String = scan.CompletedAt.Format(time.RFC3339)
	}

	_, err := s.db.Exec(
		`UPDATE scans SET target_url=?, phase=?, status=?, notes=?, completed_at=?, updated_at=? WHERE id=?`,
		scan.TargetURL, scan.Phase, scan.Status, scan.Notes,
		completedAt, scan.UpdatedAt.Format(time.RFC3339), scan.ID,
	)
	return err
}

func (s *SQLiteStore) DeleteScan(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, _ = tx.Exec(`DELETE FROM findings WHERE scan_id = ?`, id)
	_, _ = tx.Exec(`DELETE FROM targets WHERE scan_id = ?`, id)
	_, _ = tx.Exec(`DELETE FROM vuln_chains WHERE scan_id = ?`, id)

	result, err := tx.Exec(`DELETE FROM scans WHERE id = ?`, id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("scan %s not found", id)
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetFindings(scanID string) ([]types.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, type, severity, description, evidence, reproduction_steps, scan_id, target_id, cve, cwe, tags, created_at FROM findings WHERE scan_id = ? ORDER BY created_at DESC`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []types.Finding
	for rows.Next() {
		var f types.Finding
		var tagsJSON string
		if err := rows.Scan(&f.ID, &f.Type, &f.Severity, &f.Description, &f.Evidence,
			&f.ReproductionSteps, &f.ScanID, &f.TargetID, &f.CVE, &f.CWE, &tagsJSON, &f.CreatedAt); err != nil {
			return nil, err
		}
		f.Tags = parseStringArray(tagsJSON)
		findings = append(findings, f)
	}
	return findings, nil
}

func (s *SQLiteStore) CreateFinding(finding *types.Finding) error {
	tagsJSON, _ := json.Marshal(finding.Tags)
	_, err := s.db.Exec(
		`INSERT INTO findings (id, type, severity, description, evidence, reproduction_steps, scan_id, target_id, cve, cwe, tags, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding.ID, finding.Type, finding.Severity, finding.Description, finding.Evidence,
		finding.ReproductionSteps, finding.ScanID, finding.TargetID, finding.CVE, finding.CWE,
		string(tagsJSON), finding.CreatedAt.Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) ListTargets(scanID string) ([]types.Target, error) {
	rows, err := s.db.Query(
		`SELECT id, host, ports, services, tech_stack, finding_ids, scan_id, discovered_at FROM targets WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []types.Target
	for rows.Next() {
		var t types.Target
		var portsJSON, servicesJSON, techStackJSON, findingIDsJSON string
		if err := rows.Scan(&t.ID, &t.Host, &portsJSON, &servicesJSON, &techStackJSON, &findingIDsJSON, &t.ScanID, &t.DiscoveredAt); err != nil {
			return nil, err
		}
		t.Services = parseStringArray(servicesJSON)
		t.TechStack = parseStringArray(techStackJSON)
		t.Findings = parseStringArray(findingIDsJSON)
		var portStructs []types.Port
		json.Unmarshal([]byte(portsJSON), &portStructs)
		t.Ports = portStructs
		targets = append(targets, t)
	}
	return targets, nil
}

func ptrTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{Valid: true, String: t.Format(time.RFC3339)}
}

func parseStringArray(jsonStr string) []string {
	if jsonStr == "" || jsonStr == "null" {
		return []string{}
	}
	var arr []string
	json.Unmarshal([]byte(jsonStr), &arr)
	if arr == nil {
		return []string{}
	}
	return arr
}

// UpdateScanPhase updates the phase and status of a scan.
func (s *SQLiteStore) UpdateScanPhase(id string, phase types.ScanPhase, status types.ScanStatus) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE scans SET phase=?, status=?, updated_at=? WHERE id=?`,
		phase, status, now, id,
	)
	if err != nil {
		return err
	}
	log.Printf("scan %s updated: phase=%s status=%s", id, phase, status)
	return nil
}

// CreateTarget inserts a new target record.
func (s *SQLiteStore) CreateTarget(target *types.Target) error {
	portsJSON, _ := json.Marshal(target.Ports)
	servicesJSON, _ := json.Marshal(target.Services)
	techStackJSON, _ := json.Marshal(target.TechStack)
	findingJSON, _ := json.Marshal(target.Findings)

	_, err := s.db.Exec(
		`INSERT INTO targets (id, host, ports, services, tech_stack, finding_ids, scan_id, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		target.ID, target.Host, string(portsJSON), string(servicesJSON), string(techStackJSON),
		string(findingJSON), target.ScanID, target.DiscoveredAt.Format(time.RFC3339),
	)
	return err
}

// GetRunningScans returns all scans that are currently in RUNNING or PENDING state.
func (s *SQLiteStore) GetRunningScans() ([]types.Scan, error) {
	rows, err := s.db.Query(
		`SELECT id, target_url, phase, status, notes, created_at, completed_at, updated_at FROM scans WHERE status IN (?, ?)`,
		"RUNNING", "PENDING",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []types.Scan
	for rows.Next() {
		var scan types.Scan
		var completedAt sql.NullString
		if err := rows.Scan(&scan.ID, &scan.TargetURL, &scan.Phase, &scan.Status, &scan.Notes,
			&scan.CreatedAt, &completedAt, &scan.UpdatedAt); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, completedAt.String)
			scan.CompletedAt = &t
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

// BulkInsertFindings inserts multiple findings in a single transaction.
func (s *SQLiteStore) BulkInsertFindings(findings []types.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO findings (id, type, severity, description, evidence, reproduction_steps, scan_id, target_id, cve, cwe, tags, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		tagsJSON, _ := json.Marshal(f.Tags)
		if _, err := stmt.Exec(f.ID, f.Type, f.Severity, f.Description, f.Evidence,
			f.ReproductionSteps, f.ScanID, f.TargetID, f.CVE, f.CWE, string(tagsJSON),
			f.CreatedAt.Format(time.RFC3339)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// CompleteScan marks a scan as completed with the given final status.
func (s *SQLiteStore) CompleteScan(id string, status types.ScanStatus) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`UPDATE scans SET status=?, completed_at=?, updated_at=? WHERE id=?`,
		status, now.Format(time.RFC3339), now.Format(time.RFC3339), id,
	)
	return err
}

// GetFindingCount returns the number of findings for a scan.
func (s *SQLiteStore) GetFindingCount(scanID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&count)
	return count, err
}

// GetFindingsBySeverity returns findings grouped by severity for a scan.
func (s *SQLiteStore) GetFindingsBySeverity(scanID string) (map[string]int, error) {
	rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		result[strings.ToLower(severity)] = count
	}
	return result, nil
}

// healthCheck verifies the database connection is alive.
func (s *SQLiteStore) healthCheck() error {
	_, err := s.db.Exec(`SELECT 1`)
	return err
}

// GetScanStats returns aggregate statistics for all scans.
func (s *SQLiteStore) GetScanStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var totalScans, pending, running, paused, completed, failed int
	row := s.db.QueryRow(`SELECT COUNT(*) FROM scans`)
	row.Scan(&totalScans)

	row = s.db.QueryRow(`SELECT COUNT(*) FROM scans WHERE status = 'PENDING'`)
	row.Scan(&pending)

	row = s.db.QueryRow(`SELECT COUNT(*) FROM scans WHERE status = 'RUNNING'`)
	row.Scan(&running)

	row = s.db.QueryRow(`SELECT COUNT(*) FROM scans WHERE status = 'PAUSED'`)
	row.Scan(&paused)

	row = s.db.QueryRow(`SELECT COUNT(*) FROM scans WHERE status = 'COMPLETED'`)
	row.Scan(&completed)

	row = s.db.QueryRow(`SELECT COUNT(*) FROM scans WHERE status = 'FAILED'`)
	row.Scan(&failed)

	var totalFindings int
	row = s.db.QueryRow(`SELECT COUNT(*) FROM findings`)
	row.Scan(&totalFindings)

	stats["total_scans"] = totalScans
	stats["pending"] = pending
	stats["running"] = running
	stats["paused"] = paused
	stats["completed"] = completed
	stats["failed"] = failed
	stats["total_findings"] = totalFindings

	return stats, nil
}
