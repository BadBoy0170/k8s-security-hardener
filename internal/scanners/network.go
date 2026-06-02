package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ScanNetwork checks all namespaces for the absence of a default-deny NetworkPolicy,
// which is a critical baseline control to prevent lateral movement between pods.
func ScanNetwork(ctx context.Context, clientset kubernetes.Interface, clusterName string) ([]report.SecurityFinding, error) {
	var findings []report.SecurityFinding

	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		// Skip system namespaces — they have intentionally open networking
		if isSystemNamespace(ns.Name) {
			continue
		}

		policies, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list network policies in namespace %q: %w", ns.Name, err)
		}

		hasDefaultDenyIngress := false
		hasDefaultDenyEgress := false

		for _, pol := range policies.Items {
			// A default-deny policy has an empty pod selector (matches all pods)
			// and either no policyTypes (means ingress) or explicit Ingress/Egress types with no rules
			if pol.Spec.PodSelector.MatchLabels == nil && len(pol.Spec.PodSelector.MatchExpressions) == 0 {
				for _, t := range pol.Spec.PolicyTypes {
					if t == "Ingress" && len(pol.Spec.Ingress) == 0 {
						hasDefaultDenyIngress = true
					}
					if t == "Egress" && len(pol.Spec.Egress) == 0 {
						hasDefaultDenyEgress = true
					}
				}
				// If policyTypes is empty, it defaults to Ingress with empty rules = deny all ingress
				if len(pol.Spec.PolicyTypes) == 0 && len(pol.Spec.Ingress) == 0 {
					hasDefaultDenyIngress = true
				}
			}
		}

		if !hasDefaultDenyIngress {
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Severity:    report.SeverityHigh,
				RuleID:      "NETWORK-001",
				ClusterName: clusterName,
				Namespace:   ns.Name,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Description: "Namespace has no default-deny Ingress NetworkPolicy — all pods can receive traffic from any source",
				Remediation: `Apply a default-deny ingress NetworkPolicy:
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: default-deny-ingress
    namespace: ` + ns.Name + `
  spec:
    podSelector: {}
    policyTypes: ["Ingress"]`,
			})
		}

		if !hasDefaultDenyEgress {
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Severity:    report.SeverityMedium,
				RuleID:      "NETWORK-002",
				ClusterName: clusterName,
				Namespace:   ns.Name,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Description: "Namespace has no default-deny Egress NetworkPolicy — pods can initiate connections to any destination",
				Remediation: `Apply a default-deny egress NetworkPolicy with explicit DNS allow rules.`,
			})
		}
	}

	return findings, nil
}

// isSystemNamespace returns true for Kubernetes internal namespaces that should be excluded.
func isSystemNamespace(name string) bool {
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}
	return systemNamespaces[name]
}
