package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// This is the only file in the package that touches the network. It speaks the
// Anthropic Messages API directly over net/http (the root Go module stays
// dependency-free). API shape verified against the Claude API reference:
//   - POST https://api.anthropic.com/v1/messages
//   - headers: x-api-key, anthropic-version, content-type
//   - model claude-opus-4-8; a single FORCED, STRICT tool for structured output
//   - NO thinking (forced tool_choice + thinking is rejected on opus-4-8), and
//     NO temperature/top_p/top_k (all 400 on opus-4-8)
//   - check stop_reason (refusal / max_tokens) before reading content

const (
	anthropicURL     = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
	defaultModel     = "claude-opus-4-8"
	toolName         = "record_access_review"
	maxTokens        = 16000
)

// ErrNoAPIKey signals the copilot is unconfigured; the pipeline degrades to its
// deterministic output rather than blocking or fabricating a review.
var ErrNoAPIKey = errors.New("copilot: ANTHROPIC_API_KEY not set; skipping LLM access review")

// Client is a minimal Anthropic Messages client.
type Client struct {
	http   *http.Client
	apiKey string
	model  string
}

// NewClient reads ANTHROPIC_API_KEY (required) and an optional model override
// from LIFECYCLEGUARD_MODEL. Returns ErrNoAPIKey when no key is present.
func NewClient() (*Client, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, ErrNoAPIKey
	}
	model := os.Getenv("LIFECYCLEGUARD_MODEL")
	if model == "" {
		model = defaultModel
	}
	return &Client{
		http:   &http.Client{Timeout: 120 * time.Second},
		apiKey: key,
		model:  model,
	}, nil
}

type messageReq struct {
	Model      string      `json:"model"`
	MaxTokens  int         `json:"max_tokens"`
	System     string      `json:"system,omitempty"`
	Messages   []msg       `json:"messages"`
	Tools      []toolDef   `json:"tools,omitempty"`
	ToolChoice *toolChoice `json:"tool_choice,omitempty"`
}

type msg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type toolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	Strict      bool            `json:"strict"`
}

type toolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

type messageResp struct {
	StopReason  string `json:"stop_reason"`
	StopDetails *struct {
		Category    string `json:"category"`
		Explanation string `json:"explanation"`
	} `json:"stop_details"`
	Content []struct {
		Type  string          `json:"type"`
		Name  string          `json:"name"`
		Text  string          `json:"text"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// complete forces the given strict tool and returns its validated input JSON.
func (c *Client) complete(ctx context.Context, system, user, tool string, schema json.RawMessage) (json.RawMessage, error) {
	reqBody := messageReq{
		Model:     c.model,
		MaxTokens: maxTokens,
		System:    system,
		Messages:  []msg{{Role: "user", Content: user}},
		Tools: []toolDef{{
			Name:        tool,
			Description: ToolDescription,
			InputSchema: schema,
			Strict:      true,
		}},
		ToolChoice: &toolChoice{Type: "tool", Name: tool},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(raw))
	}

	var out messageResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode anthropic response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("anthropic error %s: %s", out.Error.Type, out.Error.Message)
	}
	// Guard stop_reason before trusting content. stop_details is populated only
	// on a refusal (null otherwise), so it's safe to read here.
	switch out.StopReason {
	case "refusal":
		if out.StopDetails != nil {
			return nil, fmt.Errorf("anthropic refused the access-review request: %s (%s)",
				out.StopDetails.Category, out.StopDetails.Explanation)
		}
		return nil, fmt.Errorf("anthropic refused the access-review request")
	case "max_tokens":
		return nil, fmt.Errorf("access review truncated at max_tokens; raise the limit")
	}
	for _, block := range out.Content {
		if block.Type == "tool_use" && block.Name == tool {
			return block.Input, nil
		}
	}
	return nil, fmt.Errorf("no %q tool_use block in response", tool)
}

// Chat sends a plain-text prompt (no tool) and returns the concatenated text
// reply. Used by the natural-language "ask" bar.
func (c *Client) Chat(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(messageReq{
		Model:     c.model,
		MaxTokens: 1024,
		System:    system,
		Messages:  []msg{{Role: "user", Content: user}},
	})
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(raw))
	}
	var out messageResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("anthropic error %s: %s", out.Error.Type, out.Error.Message)
	}
	if out.StopReason == "refusal" {
		return "", fmt.Errorf("the model declined to answer that")
	}
	var sb strings.Builder
	for _, b := range out.Content {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	return strings.TrimSpace(sb.String()), nil
}
