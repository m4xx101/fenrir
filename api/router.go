package api

import (
	"github.com/gin-gonic/gin"
	"github.com/m4xx101/shannon/api/middleware"
	"github.com/m4xx101/shannon/api/v1"
	mw "github.com/m4xx101/shannon/api/websocket"
	"github.com/m4xx101/shannon/pkg/config"
	"github.com/m4xx101/shannon/pkg/store"
	"time"
)

// Router holds the HTTP router and its dependencies.
type Router struct {
	gin    *gin.Engine
	hub    *mw.Hub
	store  *store.SQLiteStore
	config *config.Config
}

// NewRouter creates a new router with all middleware and handlers.
func NewRouter(cfg *config.Config, scanStore *store.SQLiteStore, wsHub *mw.Hub) *Router {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recover())
	router.Use(middleware.RequestLogger())

	// Rate limiting: 100 requests per minute per IP
	rl := middleware.NewRateLimiter(1*time.Minute, 100)
	router.Use(rl.Middleware())

	return &Router{
		gin:    router,
		hub:    wsHub,
		store:  scanStore,
		config: cfg,
	}
}

// Setup configures all routes and middleware.
func (r *Router) Setup() *gin.Engine {
	e := r.gin

	// Health check (no auth required)
	e.GET("/health", r.healthCheck)
	e.GET("/ready", r.readinessCheck)

	// WebSocket endpoint with optional auth
	ws := e.Group("/ws")
	{
		ws.GET("/realtime", r.hub.HandleWebSocket)
	}

	// API v1 routes (auth required)
	api := e.Group("/api/v1")
	api.Use(v1.AuthMiddleware())
	{
		v1.NewHandlers(r.store).RegisterRoutes(api)
	}

	// Dashboard stats (optional auth)
	dashboard := e.Group("/api/dashboard")
	dashboard.Use(v1.OptionalAuthMiddleware())
	{
		dashboard.GET("/stats", r.dashboardStats)
	}

	r.setupCORS(e)

	return e
}

func (r *Router) healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":    "ok",
		"service":   "shannon-pro-max",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"ws_clients": r.hub.ClientCount(),
	})
}

func (r *Router) readinessCheck(c *gin.Context) {
	// Check store connectivity
	if err := r.store.healthCheck(); err != nil {
		c.JSON(503, gin.H{
			"status": "unavailable",
			"reason": err.Error(),
		})
		return
	}
	c.JSON(200, gin.H{"status": "ready"})
}

func (r *Router) dashboardStats(c *gin.Context) {
	stats, err := r.store.GetScanStats()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to get stats"})
		return
	}
	stats["ws_clients"] = r.hub.ClientCount()
	c.JSON(200, stats)
}

func (r *Router) setupCORS(e *gin.Engine) {
	origins := r.config.Security.CORSOrigins
	if len(origins) == 0 {
		origins = []string{"*"}
	}

	e.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowed := false
		for _, o := range origins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}
		if allowed {
			if origin != "" {
				c.Header("Access-Control-Allow-Origin", origin)
			} else {
				c.Header("Access-Control-Allow-Origin", "*")
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Request-ID")
			c.Header("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}
