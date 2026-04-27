package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/m4xx101/shannon/api"
	"github.com/m4xx101/shannon/api/websocket"
	"github.com/m4xx101/shannon/pkg/config"
	"github.com/m4xx101/shannon/pkg/llm"
	"github.com/m4xx101/shannon/pkg/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	log.Println("shannon pro-max initializing...")

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	log.Printf("loaded config: server=%s:%d", cfg.Server.Host, cfg.Server.Port)

	// Initialize database
	scanStore, err := store.NewSQLiteStore(cfg.DatabasePath())
	if err != nil {
		log.Fatalf("database initialization failed: %v", err)
	}
	defer func() {
		if err := scanStore.Close(); err != nil {
			log.Printf("error closing database: %v", err)
		}
	}()
	log.Printf("sqlite database initialized: %s", cfg.DatabasePath())

	// Initialize LLM client
	llmClient, err := llm.New(cfg)
	if err != nil {
		log.Printf("warning: LLM client initialization failed (non-fatal): %v", err)
	} else {
		log.Println("LLM client initialized with tiered routing")
		_ = llmClient // available for workflow injection
	}

	// Initialize WebSocket hub
	wsHub := websocket.NewHub()
	go wsHub.Run()
	log.Println("websocket hub started")

	// Setup router
	router := api.NewRouter(cfg, scanStore, wsHub)
	engine := router.Setup()

	// Graceful shutdown
	srv := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:        engine,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	go func() {
		log.Printf("shannon pro-max listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	log.Println("server exited gracefully")
}

func loadConfig() (*AppConfig, error) {
	// Look for config in known locations
	paths := []string{
		"config.yaml",
		"/etc/shannon/config.yaml",
		"./config/config.yaml",
		"config/config.yaml",
	}

	var cfg *config.Config
	var err error

	for _, p := range paths {
		cfg, err = config.Load(p)
		if err == nil {
			return &AppConfig{Config: cfg}, nil
		}
	}

	// Fall back to defaults from env vars
	cfg, err = config.Load("")
	if err != nil {
		return nil, fmt.Errorf("no config file found and defaults failed: %w", err)
	}

	return &AppConfig{Config: cfg}, nil
}

// AppConfig wraps the base config with additional application-level settings.
type AppConfig struct {
	*config.Config
}

// DatabasePath returns the SQLite database path, defaulting if not set.
func (ac *AppConfig) DatabasePath() string {
	if dbPath := os.Getenv("DATABASE_PATH"); dbPath != "" {
		return dbPath
	}
	return filepath.Join(".", "data", "shannon.db")
}

// EnvOrDefault returns an environment variable value or the default.
func EnvOrDefault(envVar, fallback string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return fallback
}
