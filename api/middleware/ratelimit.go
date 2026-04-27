package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implements a sliding window rate limiter.
type RateLimiter struct {
	clients map[string]*clientLimiter
	window  time.Duration
	maxReqs int
	mu      sync.RWMutex
}

type clientLimiter struct {
	timestamps []time.Time
}

// NewRateLimiter creates a rate limiter with the given window and max requests.
func NewRateLimiter(window time.Duration, maxReqs int) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*clientLimiter),
		window:  window,
		maxReqs: maxReqs,
	}

	// Cleanup expired entries every minute
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

// Middleware returns a gin middleware that rate limits by IP.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if ip == "" {
			ip = c.RemoteIP()
		}

		if !rl.allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
				"limit": rl.maxReqs,
				"window_seconds": int(rl.window.Seconds()),
				"retry_after": int(rl.window.Seconds()),
			})
			return
		}

		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", rl.maxReqs))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", rl.remaining(ip)))
		c.Next()
	}
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	client, exists := rl.clients[key]
	if !exists {
		rl.clients[key] = &clientLimiter{timestamps: []time.Time{now}}
		return true
	}

	// Remove timestamps outside the window
	valid := filterTimestamps(client.timestamps, windowStart)
	client.timestamps = valid

	if len(client.timestamps) >= rl.maxReqs {
		return false
	}

	client.timestamps = append(client.timestamps, now)
	return true
}

func (rl *RateLimiter) remaining(key string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	client, exists := rl.clients[key]
	if !exists {
		return rl.maxReqs
	}

	windowStart := time.Now().Add(-rl.window)
	validCount := 0
	for _, t := range client.timestamps {
		if t.After(windowStart) {
			validCount++
		}
	}

	rem := rl.maxReqs - validCount
	if rem < 0 {
		return 0
	}
	return rem
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	windowStart := time.Now().Add(-rl.window)
	for key, client := range rl.clients {
		valid := filterTimestamps(client.timestamps, windowStart)
		if len(valid) == 0 {
			delete(rl.clients, key)
		} else {
			client.timestamps = valid
		}
	}
}

func filterTimestamps(timestamps []time.Time, cutoff time.Time) []time.Time {
	valid := make([]time.Time, 0, len(timestamps))
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	return valid
}
