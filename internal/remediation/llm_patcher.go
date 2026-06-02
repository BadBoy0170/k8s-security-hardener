// Package remediation provides LLM-based YAML patching for vulnerable Kubernetes manifests.
// It integrates with a locally-hosted Ollama instance via HTTP.
package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	"gopkg.in/yaml.v3"
)


// LLMPatcher sends vulnerable YAML manifests to a local Ollama instance
// and returns a security-hardened version of the YAML.
type LLMPatcher struct {
	ollamaURL string
	model     string
	client    *http.Client
}

// NewLLMPatcher creates a new LLMPatcher.
func NewLLMPatcher(ollamaURL, model string) *LLMPatcher {
	return &LLMPatcher{
		ollamaURL: strings.TrimRight(ollamaURL, "/"),
		model:     model,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// ollamaRequest is the JSON body for Ollama's /api/generate endpoint.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// ollamaResponse is the JSON response from Ollama's /api/generate endpoint.
type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// PatchFinding generates an LLM-based YAML remediation for a given security finding.
// It fetches the live resource YAML via kubectl, sends it to Ollama, and returns the patch.
// For mock/test resources (prefixed with [MOCK]), uses a synthetic YAML template instead.
func (p *LLMPatcher) PatchFinding(ctx context.Context, finding report.SecurityFinding) (string, error) {
	var rawYAML string
	var err error

	if strings.HasPrefix(finding.Description, "[MOCK]") {
		// Use a synthetic vulnerable YAML for testing without a real cluster
		rawYAML = mockVulnerableYAML(finding.Resource)
	} else {
		rawYAML, err = fetchResourceYAML(ctx, finding.Namespace, finding.Resource)
		if err != nil {
			return "", fmt.Errorf("failed to fetch resource YAML: %w", err)
		}
	}

	prompt := fmt.Sprintf(`You are a Kubernetes security expert. Analyze the following Kubernetes YAML manifest and patch it to fix this security violation:

VIOLATION: %s

REMEDIATION GUIDANCE: %s

YAML TO PATCH:
%s

Instructions:
1. Output ONLY valid, complete YAML — no markdown, no explanations, no code blocks
2. Fix runAsNonRoot: true, set runAsUser to a non-zero UID (e.g. 1000)
3. Drop ALL capabilities: add securityContext.capabilities.drop: ["ALL"]
4. Set allowPrivilegeEscalation: false
5. Set readOnlyRootFilesystem: true
6. Set privileged: false
7. Do NOT change the application logic, environment variables, or volumes

Output only the patched YAML:`,
		finding.Description,
		finding.Remediation,
		rawYAML,
	)

	patchedYAML, err := p.callOllama(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("ollama API call failed: %w", err)
	}

	patchedYAML = cleanYAMLOutput(patchedYAML)

	// Validate with kubectl dry-run
	if err := validateYAML(ctx, patchedYAML); err != nil {
		return "", fmt.Errorf("LLM output failed kubectl dry-run validation: %w", err)
	}

	return patchedYAML, nil
}

// callOllama sends the prompt to the Ollama /api/generate endpoint.
func (p *LLMPatcher) callOllama(ctx context.Context, prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:  p.model,
		Prompt: prompt,
		Stream: false,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.ollamaURL+"/api/generate", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP error calling Ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Ollama returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode Ollama response: %w", err)
	}

	return result.Response, nil
}

// fetchResourceYAML fetches the YAML of a Kubernetes resource via kubectl.
func fetchResourceYAML(ctx context.Context, namespace, resource string) (string, error) {
	// resource is in format "deployment/myapp" or "pod/myapp-abc"
	cmd := exec.CommandContext(ctx, "kubectl", "get", resource, "-n", namespace, "-o", "yaml")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("kubectl get failed: %w", err)
	}
	return string(out), nil
}

// validateYAML validates the LLM output in two tiers:
//  1. Always: structural YAML parse via gopkg.in/yaml.v3 (works on macOS, no cluster needed)
//  2. If kubectl is available and cluster is reachable: strict API-server dry-run
func validateYAML(ctx context.Context, yamlContent string) error {
	// Tier 1: structural YAML validity (works everywhere, no cluster needed)
	var doc interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &doc); err != nil {
		return fmt.Errorf("LLM output is not valid YAML: %w", err)
	}
	if doc == nil {
		return fmt.Errorf("LLM produced empty YAML output")
	}

	// Tier 2: kubectl dry-run (best-effort, skipped if no cluster)
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "--dry-run=client", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlContent)
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		// If error is just "no cluster available", treat as non-fatal
		if strings.Contains(outStr, "connection refused") ||
			strings.Contains(outStr, "dial tcp") ||
			strings.Contains(outStr, "no such host") ||
			strings.Contains(outStr, "unable to recognize") {
			// YAML passed structural check; cluster not available for strict validation
			return nil
		}
		// Any other kubectl error is a real problem with the LLM output
		return fmt.Errorf("kubectl dry-run failed: %s — %w", outStr, err)
	}

	return nil // Passed both tiers
}



// cleanYAMLOutput removes any markdown code fences the LLM might have added.
func cleanYAMLOutput(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```yaml")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	return strings.TrimSpace(raw)
}

// mockVulnerableYAML returns a synthetic privileged Deployment YAML for LLM testing.
func mockVulnerableYAML(resource string) string {
	return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-test
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-test
  template:
    metadata:
      labels:
        app: nginx-test
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        securityContext:
          privileged: true
          runAsUser: 0
          allowPrivilegeEscalation: true
        resources: {}
`
}
