package report

// SecurityFinding is the canonical data model for all findings emitted by the
// k8s-security-hardener. It is serialised as JSON and shipped to Wazuh or stdout.
type SecurityFinding struct {
	Tool        string `json:"tool"`
	Timestamp   string `json:"timestamp"`
	Severity    string `json:"severity"`   // Low | Medium | High | Critical
	RuleID      string `json:"rule_id"`    // e.g. RBAC-001, WORKLOAD-002, EBPF-001
	ClusterName string `json:"cluster_name"`
	Namespace   string `json:"namespace"`
	Resource    string `json:"resource"`   // e.g. deployment/nginx, pod/web-abc123
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	AttackPath  string `json:"attack_path,omitempty"` // Populated by graph analysis
}

// Severity constants for consistent usage across all scanners.
const (
	SeverityLow      = "Low"
	SeverityMedium   = "Medium"
	SeverityHigh     = "High"
	SeverityCritical = "Critical"
)

// ToolName is the canonical identifier written into every finding,
// used by Wazuh decoders to match the right log source.
const ToolName = "k8s-hardener"
