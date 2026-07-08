package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// AIAlertContext holds metadata for AI-based alert analysis.
type AIAlertContext struct {
	Title       string
	Description string
	AgentName   string
	AgentIP     string
	RuleID      string
	RuleLevel   int
	FullLog     string
	SourceIP    string
}

// AIClient defines the interface for AI providers.
type AIClient interface {
	EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error)
}

// --- Ollama Implementation ---

// OllamaClient is an AI client backed by Ollama.
type OllamaClient struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

type ollamaRequest struct {
	Model   string         `json:"model"`
	System  string         `json:"system,omitempty"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream"`
	Options map[string]any `json:"options,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// NewOllamaClient creates a new Ollama client.
func NewOllamaClient(url, model string) *OllamaClient {
	if url == "" {
		url = "http://localhost:11434/api/generate"
	} else if !strings.HasSuffix(url, "/api/generate") {
		if !strings.Contains(url, "/api/") {
			url = strings.TrimRight(url, "/") + "/api/generate"
		}
	}
	return &OllamaClient{
		BaseURL: url,
		Model:   model,
		Client:  &http.Client{Timeout: 90 * time.Second},
	}
}

// ollamaSystemPrompt verrouille la langue et le rôle : qwen2.5:3b dérive vers
// le chinois sans consigne de langue explicite dans le champ system.
const ollamaSystemPrompt = "Tu es un analyste SOC senior d'un homelab (Proxmox VE, conteneurs LXC, Docker, SIEM Wazuh). Tu réponds TOUJOURS et UNIQUEMENT en français. Tu es concis, factuel, sans bla-bla."

// EnrichAlert sends an alert to Ollama for analysis.
func (c *OllamaClient) EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error) {
	prompt := fmt.Sprintf(`ALERTE WAZUH:
- Machine: %s (%s)
- Règle: %s (niveau %d)
- Titre: %s
- Description: %s
- IP source: %s
- Log: %s

Détermine si c'est un faux positif ou une menace réelle en analysant le chemin du fichier et le log.
- Faux positifs fréquents : fichiers gérés par l'OS (archives LVM, mises à jour apt, backups vzdump, rotation de logs, tâches cron).
- Signaux de MENACE : fichiers cachés (nom commençant par un point), exécutables dans /tmp ou /dev/shm, noms évoquant du minage ou des outils d'attaque, webshells, modifications de /etc/passwd, /etc/shadow ou authorized_keys.

RÈGLE STRICTE : si AU MOINS UN signal de menace est présent, gravité minimum Élevée et action = investigation. Ne rationalise JAMAIS un signal de menace, même si le chemin ressemble à un emplacement système légitime.

RÉPONDS EN FRANÇAIS, EXACTEMENT 3 LIGNES:
**Analyse:** [ce qui s'est passé, 2 phrases max]
**Gravité:** [Faible|Moyenne|Élevée|Critique] (Faible si faux positif)
**Action:** [1 action concrète, ou "Aucune — faux positif probable"]`,
		alertCtx.AgentName, alertCtx.AgentIP,
		alertCtx.RuleID, alertCtx.RuleLevel,
		alertCtx.Title, alertCtx.Description,
		alertCtx.SourceIP,
		truncateForPrompt(alertCtx.FullLog, 1000),
	)

	reqBody := ollamaRequest{
		Model:  c.Model,
		System: ollamaSystemPrompt,
		Prompt: prompt,
		Stream: false,
		// num_predict borne le temps de génération sur CPU (~10-15 tok/s),
		// temperature basse limite la dérive de langue et de format.
		Options: map[string]any{
			"temperature": 0.2,
			"num_predict": 300,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama API error: %s - %s", resp.Status, string(body))
	}

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return cleanAIResponse(ollamaResp.Response), nil
}

// truncateForPrompt caps s to max runes: le prompt eval est la phase la plus
// lente sur CPU, un log verbeux ne doit pas gonfler la latence d'enrichissement.
func truncateForPrompt(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

func cleanAIResponse(response string) string {
	lowerResp := strings.ToLower(response)
	if idx := strings.LastIndex(lowerResp, "</think>"); idx != -1 {
		response = response[idx+8:]
	} else {
		reThink := regexp.MustCompile(`(?si)<think>.*?</think>`)
		response = reThink.ReplaceAllString(response, "")
	}

	startKey := "**Analyse:**"
	idx := strings.Index(response, startKey)
	if idx != -1 {
		response = response[idx:]
	}

	return strings.TrimSpace(response)
}

// --- OpenAI Implementation ---

// OpenAIClient is an AI client backed by OpenAI (or any OpenAI-compatible,
// self-hosted endpoint via BaseURL).
type OpenAIClient struct {
	APIKey  string
	Model   string
	BaseURL string // e.g. "https://api.openai.com/v1"
	Client  *http.Client
}

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

// NewOpenAIClient creates a new OpenAI client. baseURL may be empty, in which
// case the public OpenAI endpoint is used; pass a custom value to target an
// OpenAI-compatible, self-hosted endpoint.
func NewOpenAIClient(apiKey, model, baseURL string) *OpenAIClient {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAIClient{
		APIKey:  apiKey,
		Model:   model,
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// EnrichAlert sends an alert to OpenAI for analysis.
func (c *OpenAIClient) EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error) {
	systemPrompt := "Tu es un expert en cybersécurité (SOC Analyst). Ton but est d'analyser les alertes et de fournir des recommandations concises. Tu réponds toujours et uniquement en français."
	userPrompt := fmt.Sprintf(`Analyse l'alerte de sécurité suivante:
Titre: %s
Détails: %s
Machine: %s (%s)
Log: %s

Format de réponse attendu:
**Analyse:** [Résumé de la menace]
**Gravité:** [Niveau estimé]
**Action:** [Recommandation immédiate]
`, alertCtx.Title, alertCtx.Description, alertCtx.AgentName, alertCtx.AgentIP, alertCtx.FullLog)

	reqBody := openAIRequest{
		Model: c.Model,
		Messages: []openAIMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("openai API error: %s - %s", resp.Status, string(body))
	}

	var openAIResp openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return "", err
	}

	if len(openAIResp.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}

	return openAIResp.Choices[0].Message.Content, nil
}

// --- Factory ---

// NewAIClient creates an AIClient based on the provider name. openaiBaseURL is
// only used for the "openai" provider and may be empty (public OpenAI endpoint).
func NewAIClient(provider, url, apiKey, model, openaiBaseURL string) AIClient {
	slog.Info("Initializing AI Client", "provider", provider, "model", model)

	switch strings.ToLower(provider) {
	case "openai":
		if apiKey == "" {
			slog.Error("OpenAI API Key missing")
			return nil
		}
		if model == "" {
			model = "gpt-3.5-turbo"
		}
		return NewOpenAIClient(apiKey, model, openaiBaseURL)

	case "ollama":
		if url == "" {
			url = "http://localhost:11434"
		}
		if model == "" {
			model = "mistral"
		}
		return NewOllamaClient(url, model)

	default:
		slog.Warn("Unknown AI provider, defaulting to Ollama", "provider", provider)
		if url == "" {
			url = "http://localhost:11434"
		}
		if model == "" {
			model = "mistral"
		}
		return NewOllamaClient(url, model)
	}
}
