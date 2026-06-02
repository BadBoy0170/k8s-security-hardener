package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ScanWorkloads checks Deployments, DaemonSets, and StatefulSets across all namespaces
// for insecure pod security configurations.
func ScanWorkloads(ctx context.Context, clientset kubernetes.Interface, clusterName string) ([]report.SecurityFinding, error) {
	var findings []report.SecurityFinding

	// --- Deployments ---
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}
	for _, d := range deployments.Items {
		f := auditPodSpec(d.Spec.Template.Spec, "deployment/"+d.Name, d.Namespace, clusterName)
		findings = append(findings, f...)
	}

	// --- DaemonSets ---
	daemonSets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list daemonsets: %w", err)
	}
	for _, ds := range daemonSets.Items {
		f := auditPodSpec(ds.Spec.Template.Spec, "daemonset/"+ds.Name, ds.Namespace, clusterName)
		findings = append(findings, f...)
	}

	// --- StatefulSets ---
	statefulSets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list statefulsets: %w", err)
	}
	for _, ss := range statefulSets.Items {
		f := auditPodSpec(ss.Spec.Template.Spec, "statefulset/"+ss.Name, ss.Namespace, clusterName)
		findings = append(findings, f...)
	}

	return findings, nil
}

// AuditPodSpecDirect is an exported wrapper around auditPodSpec for use by the webhook.
func AuditPodSpecDirect(spec corev1.PodSpec, resource, namespace, clusterName string) []report.SecurityFinding {
	return auditPodSpec(spec, resource, namespace, clusterName)
}

// auditPodSpec inspects a single PodSpec for security misconfigurations.
func auditPodSpec(spec corev1.PodSpec, resource, namespace, clusterName string) []report.SecurityFinding {
	var findings []report.SecurityFinding
	ts := time.Now().UTC().Format(time.RFC3339)

	// Check pod-level security context
	if spec.SecurityContext != nil {
		if spec.SecurityContext.RunAsUser != nil && *spec.SecurityContext.RunAsUser == 0 {
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   ts,
				Severity:    report.SeverityHigh,
				RuleID:      "WORKLOAD-001",
				ClusterName: clusterName,
				Namespace:   namespace,
				Resource:    resource,
				Description: "Pod is configured to run as root (runAsUser: 0)",
				Remediation: "Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID (e.g., 1000).",
			})
		}
	}

	// Check individual container security contexts
	for _, c := range spec.Containers {
		if c.SecurityContext != nil {
			// Privileged container check
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				findings = append(findings, report.SecurityFinding{
					Tool:        report.ToolName,
					Timestamp:   ts,
					Severity:    report.SeverityCritical,
					RuleID:      "WORKLOAD-002",
					ClusterName: clusterName,
					Namespace:   namespace,
					Resource:    fmt.Sprintf("%s/container/%s", resource, c.Name),
					Description: "Container is running in privileged mode — has full host access",
					Remediation: "Set securityContext.privileged: false. Use specific capabilities if needed.",
				})
			}

			// Root UID on container level
			if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				findings = append(findings, report.SecurityFinding{
					Tool:        report.ToolName,
					Timestamp:   ts,
					Severity:    report.SeverityHigh,
					RuleID:      "WORKLOAD-003",
					ClusterName: clusterName,
					Namespace:   namespace,
					Resource:    fmt.Sprintf("%s/container/%s", resource, c.Name),
					Description: "Container explicitly runs as root (runAsUser: 0)",
					Remediation: "Set runAsUser to a non-zero UID. Add runAsNonRoot: true.",
				})
			}

			// Read-only root filesystem missing
			if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
				findings = append(findings, report.SecurityFinding{
					Tool:        report.ToolName,
					Timestamp:   ts,
					Severity:    report.SeverityMedium,
					RuleID:      "WORKLOAD-004",
					ClusterName: clusterName,
					Namespace:   namespace,
					Resource:    fmt.Sprintf("%s/container/%s", resource, c.Name),
					Description: "Container does not have a read-only root filesystem",
					Remediation: "Set securityContext.readOnlyRootFilesystem: true. Mount writable volumes for /tmp or app-specific paths.",
				})
			}

			// AllowPrivilegeEscalation not explicitly disabled
			if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
				findings = append(findings, report.SecurityFinding{
					Tool:        report.ToolName,
					Timestamp:   ts,
					Severity:    report.SeverityMedium,
					RuleID:      "WORKLOAD-005",
					ClusterName: clusterName,
					Namespace:   namespace,
					Resource:    fmt.Sprintf("%s/container/%s", resource, c.Name),
					Description: "Container allows privilege escalation (allowPrivilegeEscalation not set to false)",
					Remediation: "Set securityContext.allowPrivilegeEscalation: false.",
				})
			}
		}

		// Missing resource limits
		if c.Resources.Limits == nil {
			findings = append(findings, report.SecurityFinding{
				Tool:        report.ToolName,
				Timestamp:   ts,
				Severity:    report.SeverityMedium,
				RuleID:      "WORKLOAD-006",
				ClusterName: clusterName,
				Namespace:   namespace,
				Resource:    fmt.Sprintf("%s/container/%s", resource, c.Name),
				Description: "Container has no resource limits — risk of resource exhaustion / DoS",
				Remediation: "Set resources.limits.cpu and resources.limits.memory on all containers.",
			})
		}
	}

	// HostNetwork / HostPID / HostIPC checks
	if spec.HostNetwork {
		findings = append(findings, report.SecurityFinding{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityHigh,
			RuleID:      "WORKLOAD-007",
			ClusterName: clusterName,
			Namespace:   namespace,
			Resource:    resource,
			Description: "Pod uses host network namespace (hostNetwork: true)",
			Remediation: "Remove hostNetwork: true unless absolutely required. Use services for inter-pod communication.",
		})
	}

	if spec.HostPID {
		findings = append(findings, report.SecurityFinding{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityHigh,
			RuleID:      "WORKLOAD-008",
			ClusterName: clusterName,
			Namespace:   namespace,
			Resource:    resource,
			Description: "Pod uses host PID namespace (hostPID: true) — can see all host processes",
			Remediation: "Remove hostPID: true.",
		})
	}

	return findings
}
