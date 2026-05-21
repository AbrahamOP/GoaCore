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
	Title           string
	Description     string
	AgentName       string
	AgentIP         string
	RuleID          string
	RuleLevel       int
	RuleGroups      []string
	MitreIDs        []string
	MitreTactics    []string
	MitreTechniques []string
	FullLog         string
	SourceIP        string
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
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
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

// EnrichAlert sends an alert to Ollama for analysis.
func (c *OllamaClient) EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error) {
	prompt := buildSOCPrompt(alertCtx)

	reqBody := ollamaRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
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

// buildSOCPrompt constructs a SOC analyst prompt with MITRE context (when
// available) and a strict response format. The format is parseable enough to
// surface FP probability + adjusted severity downstream if needed, while
// staying readable as a Discord message.
func buildSOCPrompt(c AIAlertContext) string {
	mitre := ""
	if len(c.MitreIDs) > 0 {
		mitre = "\nMITRE ATT&CK:\n"
		for i, id := range c.MitreIDs {
			tactic := ""
			if i < len(c.MitreTactics) {
				tactic = c.MitreTactics[i]
			}
			tech := ""
			if i < len(c.MitreTechniques) {
				tech = c.MitreTechniques[i]
			}
			mitre += fmt.Sprintf("- %s — %s (%s)\n", id, tech, tactic)
		}
	}

	groups := ""
	if len(c.RuleGroups) > 0 {
		groups = "\nGROUPES WAZUH: " + strings.Join(c.RuleGroups, ", ")
	}

	return fmt.Sprintf(`Tu es un expert SOC analyst en cybersécurité. Tu analyses une alerte d'un homelab personnel (HomeLab GoaCloud — segments VLAN, Wazuh SIEM, Suricata IDS). L'environnement est domestique : peu d'utilisateurs, beaucoup d'automatisations (Docker healthchecks, agents de monitoring, jobs cron). Beaucoup d'alertes sont des faux positifs liés à l'environnement.

CONTEXTE AGENT:
- Machine: %s
- IP: %s

DÉTAILS ALERTE:
- Titre: %s
- Description: %s
- Règle ID: %s (Niveau Wazuh %d)
- IP Source: %s%s%s
- Log Brut: %s

EXEMPLE de réponse attendue (référence, ne copie pas):
**Analyse:** Tentative SSH depuis 198.51.100.5 (hors-LAN), 5 échecs puis 1 succès en 90s. Pattern brute force probable, surtout que l'IP ne mappe à aucun host connu.
**MITRE:** T1110.001 (Brute Force: Password Guessing)
**Faux positif:** Non (3/10)
**Gravité ajustée:** 8/10
**Action:** Vérifier les logs /var/log/auth.log de l'host cible, bloquer l'IP côté OPNsense (Firewall → Aliases), forcer rotation du mot de passe du compte ciblé.

TA RÉPONSE (même format, en français, concise, ~5 lignes max):
**Analyse:** [Que s'est-il passé concrètement ? Pourquoi cette alerte ?]
**MITRE:** [Technique MITRE pertinente avec ID + nom court. Si déjà tagué dans l'alerte, confirme ou corrige.]
**Faux positif:** [Oui/Non + probabilité 0-10 — 10 = sûr d'être un FP]
**Gravité ajustée:** [1-10 en tenant compte du contexte homelab]
**Action:** [Une action concrète, immédiate, exécutable. Pas de "surveillez", sois directif.]

Sois direct, technique, pas de bla-bla.`,
		c.AgentName, c.AgentIP,
		c.Title, c.Description,
		c.RuleID, c.RuleLevel,
		c.SourceIP, mitre, groups,
		c.FullLog,
	)
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

// OpenAIClient is an AI client backed by OpenAI.
type OpenAIClient struct {
	APIKey string
	Model  string
	Client *http.Client
}

type openAIRequest struct {
	Model    string           `json:"model"`
	Messages []openAIMessage  `json:"messages"`
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

// NewOpenAIClient creates a new OpenAI client.
func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	return &OpenAIClient{
		APIKey: apiKey,
		Model:  model,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

// EnrichAlert sends an alert to OpenAI for analysis.
func (c *OpenAIClient) EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error) {
	systemPrompt := "Tu es un expert SOC analyst. Tu réponds en français, concis, format strict."
	userPrompt := buildSOCPrompt(alertCtx)

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

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
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

// NewAIClient creates an AIClient based on the provider name.
func NewAIClient(provider, url, apiKey, model string) AIClient {
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
		return NewOpenAIClient(apiKey, model)

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
