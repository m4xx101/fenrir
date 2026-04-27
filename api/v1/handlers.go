package v1

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/m4xx101/shannon/pkg/types"
)

// ScanStore handles scan persistence operations.
type ScanStore interface {
	GetScans(limit, offset int) ([]types.Scan, error)
	GetScan(id string) (*types.Scan, error)
	CreateScan(scan *types.Scan) error
	UpdateScan(scan *types.Scan) error
	DeleteScan(id string) error
	GetFindings(scanID string) ([]types.Finding, error)
	CreateFinding(finding *types.Finding) error
	ListTargets(scanID string) ([]types.Target, error)
}

// Handlers holds the HTTP handlers for the v1 API.
type Handlers struct {
	store  ScanStore
	llmClient interface{} // injected LLM client for tool registration
}

// NewHandlers creates a new set of API v1 handlers.
func NewHandlers(store ScanStore) *Handlers {
	return &Handlers{store: store}
}

// RegisterRoutes sets up all v1 routes on the provided group.
func (h *Handlers) RegisterRoutes(r *gin.RouterGroup) {
	scans := r.Group("/scans")
	{
		scans.POST("", h.CreateScan)
		scans.GET("", h.ListScans)
		scans.GET("/:id", h.GetScan)
		scans.GET("/:id/findings", h.ListFindings)
		scans.POST("/:id/pause", h.PauseScan)
		scans.DELETE("/:id", h.DeleteScan)
	}

	targets := r.Group("/targets")
	{
		targets.GET("/:id/brain", h.QuerySecondBrain)
	}

	tools := r.Group("/tools")
	{
		tools.POST("/register", h.RegisterTool)
		tools.GET("", h.ListTools)
	}
}

// CreateScan handles POST /api/v1/scans
func (h *Handlers) CreateScan(c *gin.Context) {
	var req types.CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	if req.TargetURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_url is required"})
		return
	}

	phase := req.Phase
	if !phase.Valid() {
		phase = types.PhaseRECON
	}

	now := time.Now().UTC()
	scan := &types.Scan{
		ID:        generateID("scan"),
		TargetURL: req.TargetURL,
		Phase:     phase,
		Status:    types.StatusPENDING,
		Notes:     req.Notes,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateScan(scan); err != nil {
		log.Printf("failed to create scan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan"})
		return
	}

	c.JSON(http.StatusCreated, scan)
}

// ListScans handles GET /api/v1/scans
func (h *Handlers) ListScans(c *gin.Context) {
	limit := 50
	if s := c.DefaultQuery("limit", "50"); s != "" {
		fmt.Sscanf(s, "%d", &limit)
	}

	offset := 0
	if s := c.DefaultQuery("offset", "0"); s != "" {
		fmt.Sscanf(s, "%d", &offset)
	}

	scans, err := h.store.GetScans(limit, offset)
	if err != nil {
		log.Printf("failed to list scans: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scans"})
		return
	}

	if scans == nil {
		scans = []types.Scan{}
	}

	c.JSON(http.StatusOK, gin.H{
		"scans":  scans,
		"limit":  limit,
		"offset": offset,
	})
}

// GetScan handles GET /api/v1/scans/:id
func (h *Handlers) GetScan(c *gin.Context) {
	id := c.Param("id")

	scan, err := h.store.GetScan(id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		log.Printf("failed to get scan %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get scan"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// ListFindings handles GET /api/v1/scans/:id/findings
func (h *Handlers) ListFindings(c *gin.Context) {
	id := c.Param("id")

	// Verify scan exists
	if _, err := h.store.GetScan(id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		log.Printf("failed to get scan %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get scan"})
		return
	}

	findings, err := h.store.GetFindings(id)
	if err != nil {
		log.Printf("failed to list findings for scan %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list findings"})
		return
	}

	if findings == nil {
		findings = []types.Finding{}
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  id,
		"findings": findings,
		"count":    len(findings),
	})
}

// PauseScan handles POST /api/v1/scans/:id/pause
func (h *Handlers) PauseScan(c *gin.Context) {
	id := c.Param("id")

	scan, err := h.store.GetScan(id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		log.Printf("failed to get scan %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get scan"})
		return
	}

	var req types.PauseScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("invalid pause request: %v", err)
	}

	if scan.Status.IsTerminal() {
		c.JSON(http.StatusConflict, gin.H{
			"error":    "cannot pause a scan in terminal state",
			"status":   scan.Status,
		})
		return
	}

	if req.Resume {
		scan.Status = types.StatusRUNNING
	} else {
		scan.Status = types.StatusPAUSED
	}
	scan.UpdatedAt = time.Now().UTC()

	if err := h.store.UpdateScan(scan); err != nil {
		log.Printf("failed to update scan %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update scan"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// DeleteScan handles DELETE /api/v1/scans/:id
func (h *Handlers) DeleteScan(c *gin.Context) {
	id := c.Param("id")

	// Verify scan exists
	if _, err := h.store.GetScan(id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		log.Printf("failed to get scan %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get scan"})
		return
	}

	if err := h.store.DeleteScan(id); err != nil {
		log.Printf("failed to delete scan %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete scan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted": id,
		"success": true,
	})
}

// QuerySecondBrain handles GET /api/v1/targets/:id/brain
func (h *Handlers) QuerySecondBrain(c *gin.Context) {
	targetID := c.Param("id")
	query := c.Query("q")

	if query == "" {
		query = "What do we know about this target?"
	}

	// Build a placeholder result from the second brain
	// This would normally query ChromaDB
	result := gin.H{
		"target_id": targetID,
		"query":     query,
		"results":   []string{"no data indexed yet for this target"},
		"count":     0,
	}

	c.JSON(http.StatusOK, result)
}

// RegisterTool handles POST /api/v1/tools/register
type ToolRegisterRequest struct {
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"schema"`
	Server      string         `json:"server"`
}

// RegisteredTool holds tool metadata.
var registeredTools = make(map[string]ToolRegisterRequest)

// RegisterTool registers a new MCP tool definition.
func (h *Handlers) RegisterTool(c *gin.Context) {
	var req ToolRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid tool definition: %v", err)})
		return
	}

	registeredTools[req.Name] = req
	log.Printf("registered tool: %s on server %s", req.Name, req.Server)

	c.JSON(http.StatusCreated, gin.H{
		"registered": req.Name,
		"tool":       req,
	})
}

// ListTools handles GET /api/v1/tools
func (h *Handlers) ListTools(c *gin.Context) {
	toolList := make([]ToolRegisterRequest, 0, len(registeredTools))
	for _, t := range registeredTools {
		toolList = append(toolList, t)
	}

	c.JSON(http.StatusOK, gin.H{
		"tools": toolList,
		"count": len(toolList),
	})
}

// generateID produces a simple ID with prefix and timestamp for now.
// In production, use ulid or uuid.
func generateID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}
