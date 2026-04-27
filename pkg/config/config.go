package config

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	LLM         LLMConfig         `yaml:"llm"`
	Temporal    TemporalConfig    `yaml:"temporal"`
	SecondBrain SecondBrainConfig `yaml:"second_brain"`
	MCP         MCPConfig         `yaml:"mcp"`
	Auth        AuthConfig        `yaml:"auth"`
	Security    SecurityConfig    `yaml:"security"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port int    `yaml:"port" env:"SERVER_PORT"`
	Host string `yaml:"host" env:"SERVER_HOST"`
}

// LLMConfig holds LLM provider configuration.
type LLMConfig struct {
	Providers     []LLMProvider  `yaml:"providers"`
	DefaultModels DefaultModels  `yaml:"default_models"`
}

// LLMProvider defines a single LLM endpoint.
type LLMProvider struct {
	Name       string `yaml:"name"`
	BaseURL    string `yaml:"base_url"`
	APIKey     string `yaml:"api_key"`
	APIType    string `yaml:"api_type"` // openai, anthropic, openai-compatible
	MaxTokens  int    `yaml:"max_tokens"`
	RateLimitR int    `yaml:"rate_limit_rpm"` // requests per minute
}

// DefaultModels maps tier names to model identifiers.
type DefaultModels struct {
	Local        string `yaml:"local"`
	CloudCheap   string `yaml:"cloud_cheap"`
	CloudStrong  string `yaml:"cloud_strong"`
	Uncensored   string `yaml:"uncensored"`
	Abliterated  string `yaml:"abliterated"`
}

// TemporalConfig holds Temporal workflow settings.
type TemporalConfig struct {
	Address   string `yaml:"address" env:"TEMPORAL_ADDR"`
	Namespace string `yaml:"namespace"`
}

// SecondBrainConfig holds vector store settings.
type SecondBrainConfig struct {
	DataDir        string `yaml:"data_dir" env:"SECOND_BRAIN_DATA_DIR"`
	ChromaEndpoint string `yaml:"chroma_endpoint" env:"CHROMA_URL"`
}

// MCPConfig holds MCP server definitions.
type MCPConfig struct {
	Servers []MCPServer `yaml:"servers"`
}

// MCPServer defines a single MCP tool server.
type MCPServer struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Transport string          `yaml:"transport"` // sse, stdio, http
	Headers map[string]string `yaml:"headers"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	APIKeys []string `yaml:"api_keys" env:"API_KEYS"`
	JWTSecret string `yaml:"jwt_secret" env:"JWT_SECRET"`
	TokenExpiryHours int `yaml:"token_expiry_hours"`
}

// SecurityConfig holds security and sandbox settings.
type SecurityConfig struct {
	SandboxEnabled bool     `yaml:"sandbox_enabled" env:"SANDBOX_ENABLED"`
	AllowedHosts   []string `yaml:"allowed_hosts" env:"ALLOWED_HOSTS"`
	MaxRequestSizeMB int    `yaml:"max_request_size_mb"`
	CORSOrigins    []string `yaml:"cors_origins"`
}

var (
	globalConfig *Config
	configOnce   sync.Once
	configMutex  sync.RWMutex
)

// Load reads configuration from YAML file and overrides with environment variables.
func Load(configPath string) (*Config, error) {
	cfg := &Config{}

	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", configPath, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", configPath, err)
		}
	}

	applyEnvOverrides(cfg)
	applyDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// MustLoad calls Load and panics on error.
func MustLoad(configPath string) *Config {
	cfg, err := Load(configPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	SetGlobal(cfg)
	return cfg
}

// Get returns the globally set config.
func Get() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	if globalConfig == nil {
		panic("global config not set — call MustLoad or SetGlobal first")
	}
	return globalConfig
}

// SetGlobal sets the global config (thread-safe).
func SetGlobal(cfg *Config) {
	configMutex.Lock()
	defer configMutex.Unlock()
	globalConfig = cfg
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("SERVER_PORT"); v != "" {
		cfg.Server.Port = parseInt(v, cfg.Server.Port)
	}
	if v := os.Getenv("SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("OPENROUTER_API_KEY"); v != "" {
		updateProviderKey(cfg, "openrouter", v)
	}
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		updateProviderKey(cfg, "openai", v)
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		updateProviderKey(cfg, "anthropic", v)
	}
	if v := os.Getenv("OLLAMA_BASE_URL"); v != "" {
		updateProviderURL(cfg, "ollama", v)
	}
	if v := os.Getenv("TEMPORAL_ADDR"); v != "" {
		cfg.Temporal.Address = v
	}
	if v := os.Getenv("CHROMA_URL"); v != "" {
		cfg.SecondBrain.ChromaEndpoint = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	if v := os.Getenv("API_KEYS"); v != "" {
		cfg.Auth.APIKeys = splitCSV(v)
	}
	if v := os.Getenv("DATABASE_PATH"); v != "" {
		// stored in env only, not in struct; handled by main
	}
	if v := os.Getenv("SECOND_BRAIN_DATA_DIR"); v != "" {
		cfg.SecondBrain.DataDir = v
	}
	if v := os.Getenv("SANDBOX_ENABLED"); v != "" {
		cfg.Security.SandboxEnabled = parseBool(v, cfg.Security.SandboxEnabled)
	}
	if v := os.Getenv("ALLOWED_HOSTS"); v != "" {
		cfg.Security.AllowedHosts = splitCSV(v)
	}
}

func updateProviderKey(cfg *Config, name, key string) {
	for i := range cfg.LLM.Providers {
		if cfg.LLM.Providers[i].Name == name {
			cfg.LLM.Providers[i].APIKey = key
			return
		}
	}
	cfg.LLM.Providers = append(cfg.LLM.Providers, LLMProvider{
		Name:    name,
		APIKey:  key,
		APIType: "openai-compatible",
	})
}

func updateProviderURL(cfg *Config, name, url string) {
	for i := range cfg.LLM.Providers {
		if cfg.LLM.Providers[i].Name == name {
			cfg.LLM.Providers[i].BaseURL = url
			return
		}
	}
	cfg.LLM.Providers = append(cfg.LLM.Providers, LLMProvider{
		Name:    name,
		BaseURL: url,
		APIType: "openai-compatible",
	})
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Temporal.Namespace == "" {
		cfg.Temporal.Namespace = "shannon"
	}
	if cfg.Auth.TokenExpiryHours == 0 {
		cfg.Auth.TokenExpiryHours = 24
	}
	if cfg.Security.MaxRequestSizeMB == 0 {
		cfg.Security.MaxRequestSizeMB = 10
	}
	if len(cfg.Security.CORSOrigins) == 0 {
		cfg.Security.CORSOrigins = []string{"*"}
	}
	if len(cfg.LLM.Providers) == 0 {
		cfg.LLM.Providers = defaultProviders()
	}
	if cfg.LLM.DefaultModels.Local == "" {
		cfg.LLM.DefaultModels.Local = "qwen3:8b"
	}
	if cfg.LLM.DefaultModels.CloudCheap == "" {
		cfg.LLM.DefaultModels.CloudCheap = "openai/gpt-4o-mini"
	}
	if cfg.LLM.DefaultModels.CloudStrong == "" {
		cfg.LLM.DefaultModels.CloudStrong = "openrouter/openai/o3"
	}
	if cfg.LLM.DefaultModels.Uncensored == "" {
		cfg.LLM.DefaultModels.Uncensored = "local/uncensored-70b"
	}
	if cfg.LLM.DefaultModels.Abliterated == "" {
		cfg.LLM.DefaultModels.Abliterated = "local/abliterated-70b"
	}
}

func defaultProviders() []LLMProvider {
	return []LLMProvider{
		{
			Name:       "ollama",
			BaseURL:    "http://localhost:11434/v1",
			APIType:    "openai-compatible",
			MaxTokens:  8192,
			RateLimitR: 60,
		},
		{
			Name:       "openrouter",
			BaseURL:    "https://openrouter.ai/api/v1",
			APIKey:     "",
			APIType:    "openai-compatible",
			MaxTokens:  32768,
			RateLimitR: 200,
		},
	}
}

func validateConfig(cfg *Config) error {
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}
	if cfg.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET must not be empty")
	}
	if len(cfg.Auth.JWTSecret) < 16 {
		return fmt.Errorf("JWT_SECRET must be at least 16 characters")
	}
	return nil
}

func parseInt(s string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func parseBool(s string, fallback bool) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return fallback
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
