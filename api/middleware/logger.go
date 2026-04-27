package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestLogger returns a gin middleware that logs each request with timing.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		method := c.Request.Method
		path := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			path = path + "?" + c.Request.URL.RawQuery
		}
		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Get the auth identity if set
		authIdentity := "anonymous"
		if auth, exists := c.Get("auth"); exists {
			if actx, ok := auth.(struct {
				AuthMethod string
				Identity   string
			}); ok {
				authIdentity = actx.Identity
			}
		}

		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()
		reqID := c.GetHeader("X-Request-ID")
		if reqID == "" {
			reqID = "-"
		}

		logEntry := logFormat{
			Timestamp:  start.Format(time.RFC3339),
			ReqID:      reqID,
			Method:     method,
			Path:       path,
			Status:     status,
			Duration:   duration,
			IP:         ip,
			UserAgent:  userAgent,
			Auth:       authIdentity,
		}

		log.Printf("%s | %s | %s | %d | %s | %s | %s",
			logEntry.ReqID, logEntry.Method, logEntry.Path, logEntry.Status,
			logEntry.Duration, logEntry.IP, logEntry.Auth)
	}
}

type logFormat struct {
	Timestamp string
	ReqID     string
	Method    string
	Path      string
	Status    int
	Duration  time.Duration
	IP        string
	UserAgent string
	Auth      string
}

// RecoveryWithLog returns a recovery middleware that logs panics.
func RecoveryWithLog() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, err any) {
		log.Printf("PANIC: %v | method=%s | path=%s | ip=%s",
			err, c.Request.Method, c.Request.URL.Path, c.ClientIP())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
	})
}
