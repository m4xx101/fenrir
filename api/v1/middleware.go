package v1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/m4xx101/shannon/pkg/config"
)

// AuthContext holds the authenticated identity.
type AuthContext struct {
	AuthMethod string `json:"auth_method"` // "api_key" or "jwt"
	Identity   string `json:"identity"`
	Scopes     []string `json:"scopes,omitempty"`
	ExpireAt   int64  `json:"expire_at,omitempty"`
}

// AuthMiddleware returns a gin middleware that validates either an API key or a JWT token.
func AuthMiddleware() gin.HandlerFunc {
	cfg := config.Get()

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		apiKeyHeader := c.GetHeader("X-API-Key")

		// Try API key first
		if apiKeyHeader != "" {
			if validAPIKey(cfg, apiKeyHeader) {
				c.Set("auth", AuthContext{
					AuthMethod: "api_key",
					Identity:   maskKey(apiKeyHeader),
				})
				c.Next()
				return
			}
		}

		// Try JWT
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			ctx, err := validateJWT(cfg, token)
			if err == nil {
				c.Set("auth", ctx)
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "valid API key (X-API-Key) or JWT Bearer token required",
		})
	}
}

func validAPIKey(cfg *config.Config, key string) bool {
	for _, validKey := range cfg.Auth.APIKeys {
		if secureCompare(key, validKey) {
			return true
		}
	}
	return false
}

// secureCompare performs a timing-safe string comparison.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

// maskKey hides most of the API key for logging.
func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// validateJWT decodes and validates a JWT token.
// This is a minimal HS256 JWT implementation without external dependencies.
func validateJWT(cfg *config.Config, token string) (AuthContext, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return AuthContext{}, fmt.Errorf("invalid JWT format")
	}

	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return AuthContext{}, fmt.Errorf("invalid JWT header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return AuthContext{}, fmt.Errorf("invalid JWT header: %w", err)
	}

	if header.Alg != "HS256" {
		return AuthContext{}, fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
	}

	verifySig(parts[0], parts[1], parts[2], cfg.Auth.JWTSecret)

	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return AuthContext{}, fmt.Errorf("invalid JWT claims: %w", err)
	}

	var claims struct {
		Sub    string `json:"sub"`
		Exp    int64  `json:"exp"`
		Issued int64  `json:"iat"`
		Scopes string `json:"scopes"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return AuthContext{}, fmt.Errorf("invalid JWT claims: %w", err)
	}

	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return AuthContext{}, fmt.Errorf("token expired")
	}

	scopes := []string{}
	if claims.Scopes != "" {
		scopes = strings.Split(claims.Scopes, ",")
	}

	return AuthContext{
		AuthMethod: "jwt",
		Identity:   claims.Sub,
		Scopes:     scopes,
		ExpireAt:   claims.Exp,
	}, nil
}

func verifySig(part0, part1, part2, secret string) error {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(part0 + "." + part1))
	expected := base64URLEncode(mac.Sum(nil))

	if part2 != expected {
		return fmt.Errorf("invalid JWT signature")
	}
	return nil
}

func base64URLDecode(s string) ([]byte, error) {
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// OptionalAuthMiddleware allows unauthenticated access but sets auth context if present.
func OptionalAuthMiddleware() gin.HandlerFunc {
	cfg := config.Get()

	return func(c *gin.Context) {
		apiKeyHeader := c.GetHeader("X-API-Key")
		authHeader := c.GetHeader("Authorization")

		if apiKeyHeader != "" && validAPIKey(cfg, apiKeyHeader) {
			c.Set("auth", AuthContext{
				AuthMethod: "api_key",
				Identity:   maskKey(apiKeyHeader),
			})
		} else if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			ctx, err := validateJWT(cfg, token)
			if err == nil {
				c.Set("auth", ctx)
			}
		}

		c.Next()
	}
}
