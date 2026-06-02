package scanners

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ScanSecrets inspects all workloads for secrets exposed as plaintext environment variables,
// and identifies any Kubernetes Secret objects that may be overly permissive.
func ScanSecrets(ctx context.Context, clientset kubernetes.Interface, clusterName string) ([]report.SecurityFinding, error) {
	var findings []report.SecurityFinding
	ts := time.Now().UTC().Format(time.RFC3339)

	// Check deployments for plaintext secrets in env vars
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	for _, d := range deployments.Items {
		for _, c := range d.Spec.Template.Spec.Containers {
			for _, env := range c.Env {
				// Detect sensitive variable names with hardcoded values (not sourced from SecretKeyRef)
				if isSensitiveEnvName(env.Name) && env.Value != "" && env.ValueFrom == nil {
					findings = append(findings, report.SecurityFinding{
						Tool:        report.ToolName,
						Timestamp:   ts,
						Severity:    report.SeverityHigh,
						RuleID:      "SECRET-001",
						ClusterName: clusterName,
						Namespace:   d.Namespace,
						Resource:    fmt.Sprintf("deployment/%s/container/%s", d.Name, c.Name),
						Description: fmt.Sprintf("Environment variable '%s' contains a hardcoded value — should reference a Kubernetes Secret", env.Name),
						Remediation: "Replace the hardcoded env value with secretKeyRef or use a secret management tool like Vault.",
					})
				}
			}
		}
	}

	// Audit all Kubernetes Secret objects for suspicious types/names
	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, s := range secrets.Items {
		// Skip system secrets
		if strings.HasPrefix(s.Name, "default-token") || strings.HasPrefix(s.Namespace, "kube-") {
			continue
		}

		// Flag secrets in the default namespace (common misconfiguration)
		if s.Namespace == "default" {
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   ts,
				Severity:    report.SeverityMedium,
				RuleID:      "SECRET-002",
				ClusterName: clusterName,
				Namespace:   s.Namespace,
				Resource:    "secret/" + s.Name,
				Description: "Kubernetes Secret exists in the 'default' namespace — risk of unintended access by default service accounts",
				Remediation: "Move secrets to application-specific namespaces and ensure RBAC limits access.",
			})
		}

		// Flag Opaque secrets with suspicious key names
		for key := range s.Data {
			if isSensitiveEnvName(key) {
				findings = append(findings, report.SecurityFinding{
					Tool:        report.ToolName,
					Timestamp:   ts,
					Severity:    report.SeverityLow,
					RuleID:      "SECRET-003",
					ClusterName: clusterName,
					Namespace:   s.Namespace,
					Resource:    fmt.Sprintf("secret/%s (key: %s)", s.Name, key),
					Description: "Secret contains a key with a sensitive name — verify it is properly scoped and not over-shared",
					Remediation: "Audit which pods mount this secret. Apply strict RBAC. Consider using an external secrets operator.",
				})
			}
		}
	}

	return findings, nil
}

// isSensitiveEnvName returns true for common names associated with credentials/tokens.
func isSensitiveEnvName(name string) bool {
	upper := strings.ToUpper(name)
	keywords := []string{
		"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
		"PRIVATE_KEY", "ACCESS_KEY", "AUTH", "CREDENTIAL", "DB_PASS",
		"AWS_SECRET", "AZURE_KEY", "GCP_KEY",
	}
	for _, kw := range keywords {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}
