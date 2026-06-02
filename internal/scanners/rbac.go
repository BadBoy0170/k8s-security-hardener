package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ScanRBAC iterates over ClusterRoles, Roles, ClusterRoleBindings, and RoleBindings,
// flagging dangerous permissions such as wildcards and pod exec/portforward access.
func ScanRBAC(ctx context.Context, clientset kubernetes.Interface, clusterName string) ([]report.SecurityFinding, error) {
	var findings []report.SecurityFinding

	// --- ClusterRoles ---
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoles: %w", err)
	}

	// Map of dangerous ClusterRole names for fast lookup during binding scan
	dangerousClusterRoles := map[string]bool{}

	for _, cr := range clusterRoles.Items {
		if isCriticalRole(cr.Rules) {
			dangerousClusterRoles[cr.Name] = true
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Severity:    report.SeverityCritical,
				RuleID:      "RBAC-001",
				ClusterName: clusterName,
				Namespace:   "cluster-scoped",
				Resource:    "clusterrole/" + cr.Name,
				Description: "ClusterRole has wildcard verbs and resources — grants full cluster access",
				Remediation: "Remove wildcard rules and apply least-privilege permissions. Replace '*' verbs/resources with explicit lists.",
			})
		}

		if hasExecAccess(cr.Rules) {
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Severity:    report.SeverityHigh,
				RuleID:      "RBAC-002",
				ClusterName: clusterName,
				Namespace:   "cluster-scoped",
				Resource:    "clusterrole/" + cr.Name,
				Description: "ClusterRole grants pods/exec or pods/portforward — allows interactive shell access to any pod",
				Remediation: "Remove pods/exec and pods/portforward sub-resource permissions. Use audit logging for legitimate exec needs.",
			})
		}
	}

	// --- ClusterRoleBindings — find subjects bound to dangerous cluster roles ---
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)
	}

	for _, crb := range crbs.Items {
		if dangerousClusterRoles[crb.RoleRef.Name] {
			for _, subject := range crb.Subjects {
				findings = append(findings, report.SecurityFinding{
					Tool:        report.ToolName,
					Timestamp:   time.Now().UTC().Format(time.RFC3339),
					Severity:    report.SeverityCritical,
					RuleID:      "RBAC-003",
					ClusterName: clusterName,
					Namespace:   "cluster-scoped",
					Resource:    fmt.Sprintf("clusterrolebinding/%s → %s/%s", crb.Name, subject.Kind, subject.Name),
					Description: fmt.Sprintf("Subject '%s/%s' is bound to wildcard ClusterRole '%s'", subject.Kind, subject.Name, crb.RoleRef.Name),
					Remediation: "Audit this binding. Replace the wildcard role with a minimal custom role. Remove unused service account bindings.",
				})
			}
		}
	}

	// --- Namespace-scoped Roles ---
	roles, err := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Roles: %w", err)
	}

	for _, r := range roles.Items {
		if isCriticalRole(r.Rules) {
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Severity:    report.SeverityHigh,
				RuleID:      "RBAC-004",
				ClusterName: clusterName,
				Namespace:   r.Namespace,
				Resource:    "role/" + r.Name,
				Description: "Namespace Role has wildcard verbs and resources",
				Remediation: "Restrict to explicit resources and verbs needed by the workload.",
			})
		}
	}

	return findings, nil
}

// isCriticalRole returns true if any policy rule uses wildcards for both verbs and resources.
func isCriticalRole(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if containsWildcard(rule.Verbs) && containsWildcard(rule.Resources) {
			return true
		}
	}
	return false
}

// hasExecAccess returns true if the role grants pods/exec or pods/portforward.
func hasExecAccess(rules []rbacv1.PolicyRule) bool {
	dangerousSubResources := map[string]bool{
		"pods/exec":        true,
		"pods/portforward": true,
		"pods/attach":      true,
	}
	for _, rule := range rules {
		for _, sr := range rule.Resources {
			if dangerousSubResources[sr] {
				return true
			}
		}
	}
	return false
}

func containsWildcard(slice []string) bool {
	for _, v := range slice {
		if v == "*" {
			return true
		}
	}
	return false
}
