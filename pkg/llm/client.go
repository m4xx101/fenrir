package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/m4xx101/shannon/pkg/config"
	"github.com/m4xx101/shannon/pkg/types"
)

// LLMClient defines the interface for interacting with LLM providers.
type LLMClient interface {
	Chat(messages []types.LLMMessage, tools []types.ToolDef) (response *types.LLMResponse, usage types.LLMUsage, err error)
	ChatWithTier(tier types.LLMTier, messages []types.LLMMessage, tools []types.ToolDef) (response *types.LLMResponse, usage types.LLMUsage, err error)
	GetProviderForTier(tier types.LLMTier) (Provider, error)
}

// Provider is a single LLM provider backend.
type Provider interface {
	Name() string
	Type() string
	Chat(messages []types.LLMMessage, tools []types.ToolDef) (*types.LLMResponse, types.LLMUsage, error)
}

type tieredClient struct {
	providers map[string]Provider
	providerOrder map[types.LLMTier]string // tier -> provider name
	mu          sync.RWMutex
}

// New creates a new tiered LLM client from config.
func New(cfg *config.Config) (LLMClient, error) {
	client := &tieredClient{
		providers:     make(map[string]Provider),
		providerOrder: make(map[types.LLMTier]string),
	}

	for _, pc := range cfg.LLM.Providers {
		var p Provider
		var err error

		switch strings.ToLower(pc.APIType) {
		case "openai-compatible", "openai", "openrouter":
			p, err = NewOpenAICompatibleProvider(pc)
		default:
			p, err = NewOpenAICompatibleProvider(pc)
		}

		if err != nil {
			return nil, fmt.Errorf("creating provider %s: %w", pc.Name, err)
		}
		client.providers[pc.Name] = p
	}

	// Map tiers to providers based on default models
	client.providerOrder[types.TierLocal] = "ollama"
	client.providerOrder[types.TierCloudCheap] = "openrouter"
	client.providerOrder[types.TierCloudStrong] = "openrouter"
	client.providerOrder[types.TierUncensored] = "ollama"
	client.providerOrder[types.TierAbliterated] = "ollama"

	return client, nil
}

// GetProviderForTier returns the provider configured for a tier.
func (c *tieredClient) GetProviderForTier(tier types.LLMTier) (Provider, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	name, ok := c.providerOrder[tier]
	if !ok {
		return nil, fmt.Errorf("unknown tier: %s", tier)
	}

	provider, ok := c.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q not configured for tier %s", name, tier)
	}

	return provider, nil
}

// Chat sends a chat request to the default provider (cloud strong).
func (c *tieredClient) Chat(messages []types.LLMMessage, tools []types.ToolDef) (*types.LLMResponse, types.LLMUsage, error) {
	return c.ChatWithTier(types.TierCloudStrong, messages, tools)
}

// ChatWithTier sends a chat request to the provider for the specified tier.
func (c *tieredClient) ChatWithTier(tier types.LLMTier, messages []types.LLMMessage, tools []types.ToolDef) (*types.LLMResponse, types.LLMUsage, error) {
	provider, err := c.GetProviderForTier(tier)
	if err != nil {
		return nil, types.LLMUsage{}, err
	}

	return provider.Chat(messages, tools)
}

// OpenAICompatibleProvider implements the Provider interface for OpenAI-format APIs.
type OpenAICompatibleProvider struct {
	name        string
	baseURL     string
	apiKey      string
	apiType     string
	maxTokens   int
	rateLimitRPM int
	client      *http.Client
}

// NewOpenAICompatibleProvider creates a new OpenAI-compatible provider.
func NewOpenAICompatibleProvider(cfg config.LLMProvider) (*OpenAICompatibleProvider, error) {
	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}
	rpm := cfg.RateLimitR
	if rpm == 0 {
		rpm = 60
	}
	return &OpenAICompatibleProvider{
		name:         cfg.Name,
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:       cfg.APIKey,
		apiType:      cfg.APIType,
		maxTokens:    maxTokens,
		rateLimitRPM: rpm,
		client: &http.Client{
			Timeout: 300,
		},
	}, nil
}

// Name returns the provider name.
func (p *OpenAICompatibleProvider) Name() string { return p.name }

// Type returns the provider API type.
func (p *OpenAICompatibleProvider) Type() string { return p.apiType }

// openAIChatPayload matches the OpenAI chat completions request format.
type openAIChatPayload struct {
	Model       string                `json:"model"`
	Messages    []openAIMessage       `json:"messages"`
	Tools       []openAITool          `json:"tools,omitempty"`
	MaxTokens   int                   `json:"max_tokens,omitempty"`
	Temperature float64               `json:"temperature,omitempty"`
	Stream      bool                  `json:"stream"`
	TopP        float64               `json:"top_p,omitempty"`
}

type openAIMessage struct {
	Role       string          `json:"role"`
	Content    string          `json:"content,omitempty"`
	Name       string          `json:"name,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type openAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openAIFunctionCall `json:"function"`
}

type openAIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openAITool struct {
	Type     string                 `json:"type"`
	Function openAIToolFunction     `json:"function"`
}

type openAIToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// openAIChatResponse matches the OpenAI chat completions response format.
type openAIChatResponse struct {
	ID      string   `json:"id"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []struct {
		Index        int             `json:"index"`
		FinishReason string          `json:"finish_reason"`
		Message      openAIOutMessage `json:"message"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

type openAIOutMessage struct {
	Role      string                  `json:"role"`
	Content   string                  `json:"content"`
	ToolCalls []outToolCall           `json:"tool_calls"`
}

type outToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openAIFunctionCall `json:"function"`
}

// Chat sends a chat request and parses the response.
func (p *OpenAICompatibleProvider) Chat(messages []types.LLMMessage, tools []types.ToolDef) (*types.LLMResponse, types.LLMUsage, error) {
	payload := openAIChatPayload{
		Model:     p.getModelForTier(),
		MaxTokens: p.maxTokens,
		Stream:    false,
	}

	for _, m := range messages {
		om := openAIMessage{
			Role:       string(m.Role),
			Content:    m.Content,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			argsJSON, _ := json.Marshal(tc.Arguments)
			om.ToolCalls = append(om.ToolCalls, openAIToolCall{
				ID:   tc.ID,
				Type: "function",
				Function: openAIFunctionCall{
					Name:      tc.Name,
					Arguments: string(argsJSON),
				},
			})
		}
		payload.Messages = append(payload.Messages, om)
	}

	for _, t := range tools {
		payload.Tools = append(payload.Tools, openAITool{
			Type: "function",
			Function: openAIToolFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			},
		})
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, types.LLMUsage{}, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return nil, types.LLMUsage{}, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, types.LLMUsage{}, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, types.LLMUsage{}, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, types.LLMUsage{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var apiResp openAIChatResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, types.LLMUsage{}, fmt.Errorf("parsing response: %w (body: %s)", err, string(body))
	}

	if apiResp.Error != nil {
		return nil, types.LLMUsage{}, fmt.Errorf("API error [%s]: %s", apiResp.Error.Type, apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return nil, types.LLMUsage{}, fmt.Errorf("empty choices in response")
	}

	choice := apiResp.Choices[0]
	result := &types.LLMResponse{
		Content:      choice.Message.Content,
		Role:         types.MessageRole(choice.Message.Role),
		FinishReason: choice.FinishReason,
	}

	for _, tc := range choice.Message.ToolCalls {
		var args map[string]any
		json.Unmarshal([]byte(tc.Function.Arguments), &args)
		result.ToolCalls = append(result.ToolCalls, types.ToolCall{
			ID:        tc.ID,
			Type:      tc.Type,
			Name:      tc.Function.Name,
			Arguments: args,
		})
	}

	var usage types.LLMUsage
	if apiResp.Usage != nil {
		usage = types.LLMUsage{
			PromptTokens:     apiResp.Usage.PromptTokens,
			CompletionTokens: apiResp.Usage.CompletionTokens,
			TotalTokens:      apiResp.Usage.TotalTokens,
		}
	}

	return result, usage, nil
}

func (p *OpenAICompatibleProvider) getModelForTier() string {
	if strings.Contains(p.baseURL, "11434") || p.name == "ollama" {
		cfg := config.Get()
		return cfg.LLM.DefaultModels.Local
	}
	if strings.Contains(p.baseURL, "openrouter") || p.name == "openrouter" {
		cfg := config.Get()
		return cfg.LLM.DefaultModels.CloudStrong
	}
	return "gpt-4o"
}

// SelectTierForTask chooses an LLM tier based on task description.
func SelectTierForTask(taskDescription string) types.LLMTier {
	desc := strings.ToLower(taskDescription)

	if strings.Contains(desc, "exploit") || strings.Contains(desc, "attack") {
		return types.TierUncensored
	}
	if strings.Contains(desc, "chain") || strings.Contains(desc, "complex") {
		return types.TierAbliterated
	}
	if strings.Contains(desc, "deep analysis") || strings.Contains(desc, "strategic") || strings.Contains(desc, "reverse") {
		return types.TierCloudStrong
	}
	if strings.Contains(desc, "summary") || strings.Contains(desc, "format") || strings.Contains(desc, "list") {
		return types.TierCloudCheap
	}

	return types.TierCloudStrong
}
