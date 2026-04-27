package types

// MessageRole represents the role of a message in an LLM conversation.
type MessageRole string

const (
	RoleSystem    MessageRole = "system"
	RoleUser      MessageRole = "user"
	RoleAssistant MessageRole = "assistant"
	RoleTool      MessageRole = "tool"
)

func (r MessageRole) String() string {
	return string(r)
}

func (r MessageRole) Valid() bool {
	switch r {
	case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		return true
	}
	return false
}

// LLMMessage represents a single message in a conversation with an LLM.
type LLMMessage struct {
	Role       MessageRole `json:"role"`
	Content    string      `json:"content,omitempty"`
	Name       string      `json:"name,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
}

// ToolCall represents a function/tool call made by an LLM.
type ToolCall struct {
	ID        string           `json:"id"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Arguments map[string]any    `json:"arguments"`
}

// ToolResult represents the result returned from executing a tool call.
type ToolResult struct {
	ID        string `json:"id"`
	Content   string `json:"content"`
	ToolCallID string `json:"tool_call_id"`
}

// ToolDef defines a tool/function available for LLM use.
type ToolDef struct {
	Type        string        `json:"type"`
	Function    FunctionDef   `json:"function"`
}

// FunctionDef defines the schema for a tool function.
type FunctionDef struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Parameters  map[string]any    `json:"parameters"`
}

// LLMUsage tracks token consumption from an LLM response.
type LLMUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// LLMResponse represents a complete response from an LLM provider.
type LLMResponse struct {
	Content   string
	Role      MessageRole
	ToolCalls []ToolCall
	Usage     LLMUsage
	FinishReason string
}

// Conversation represents a full conversation history.
type Conversation struct {
	ID        string       `json:"id"`
	Messages  []LLMMessage `json:"messages"`
	ToolDefs  []ToolDef    `json:"tools,omitempty"`
	SystemPrompt string    `json:"system_prompt,omitempty"`
}
