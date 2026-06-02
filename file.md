Markdown
# Kubernetes Security Hardener: Enterprise Architecture & Implementation Guide

This document outlines the complete, end-to-end architecture for building an advanced Kubernetes Security Hardener in Go, encompassing static scanning, graph-based attack path analysis, eBPF runtime detection, LLM auto-remediation, Admission Control, and deep integration with Wazuh (SIEM/SOAR).

---

## 1. Project Directory Structure

```text
k8s-sec-hardener/
├── cmd/
│   ├── scanner/main.go           # CLI / CronJob entrypoint for scanning
│   └── webhook/main.go           # Admission controller entrypoint
├── internal/
│   ├── auth/
│   │   └── client.go             # K8s API authentication (in-cluster/kubeconfig)
│   ├── scanners/
│   │   ├── workloads.go          # Checks for privileged, root, missing limits
│   │   ├── rbac.go               # Checks for wildcard permissions, pod/exec
│   │   ├── secrets.go            # Checks for exposed/unencrypted secrets
│   │   └── network.go            # Checks for default-deny network policies
│   ├── graph/
│   │   └── attack_path.go        # gonum/graph implementation for mapping exploit paths
│   ├── ebpf/
│   │   ├── bpf_bpfeb.go          # Compiled eBPF bytecode (generated)
│   │   └── runtime.go            # cilium/ebpf loader and runtime monitor
│   ├── remediation/
│   │   └── llm_patcher.go        # Local LLM (Ollama) integration for YAML patching
│   ├── webhook/
│   │   └── validator.go          # K8s ValidatingWebhookConfiguration logic
│   └── report/
│       ├── models.go             # Vulnerability JSON schemas
│       ├── wazuh_shipper.go      # HTTP/Syslog client for shipping logs to Wazuh
│       └── console.go            # CLI output formatter
├── deployments/
│   ├── scanner-cronjob.yaml      # Manifest for running the scanner periodically
│   ├── webhook-deployment.yaml   # Manifest for the admission controller
│   └── wazuh-active-response.sh  # Script for Wazuh agent to execute remediations
├── go.mod
└── go.sum
2. Core Modules Implementation
A. The Engine & Scanners (internal/scanners/)
Written in Go using k8s.io/client-go. The engine fetches state and evaluates rules.

RBAC Scanner: Iterates over ClusterRoleBindings. If it finds subjects bound to a Role with verbs: ["*"] and resources: ["*"], it flags a Critical finding.

Workload Scanner: Checks PodSecurityContext across Deployments/DaemonSets. Flags runAsUser: 0 (Root) or privileged: true.

B. Graph-Based Attack Path Analysis (internal/graph/)
Uses gonum/graph to map out relationships.

Nodes: Pods, ServiceAccounts, Secrets, Roles.

Edges: "Has ServiceAccount", "Has Permission", "Mounts Secret".

Logic: Run Dijkstra’s algorithm to find the shortest path from a public-facing Pod to a ClusterAdmin RoleBinding. If a path exists, escalate the alert severity to Critical.

C. eBPF Runtime Audit (internal/ebpf/)
Uses cilium/ebpf to attach to Linux kernel tracepoints.

Target: Hook into sys_enter_execve.

Detection: If a container running a standard web app (e.g., Nginx) suddenly executes curl or /bin/bash, the eBPF program captures the PID and container ID, sending a runtime alert back to the Go engine.

D. LLM Auto-Remediation (internal/remediation/)
Integrates with a locally hosted LLM (e.g., Ollama running llama3 or codellama).

Input: The raw YAML of a vulnerable Deployment and the specific security violation.

Prompt: "You are a K8s security expert. Patch the following YAML to enforce runAsNonRoot: true and drop ALL capabilities. Output only valid YAML."

Output: The Go engine applies a dry-run kubectl patch to validate the LLM's output before suggesting it to the user.

E. Admission Controller (internal/webhook/)
Shifts security "left" by blocking bad deployments.

Runs as an HTTPS server inside the cluster.

Intercepts AdmissionReview requests. If the incoming object fails the internal scanners checks, it responds with allowed: false and a customized rejection message.

3. Wazuh Integration (SIEM & SOAR) - Deep Dive
Wazuh will act as your central brain for monitoring the K8s Hardener's output and triggering automated responses.

Step 3.1: Data Formatting (Go to Wazuh)
Your Go binary must output logs in a structured JSON format that Wazuh can parse easily.

internal/report/models.go

Go
type SecurityFinding struct {
    Tool        string `json:"tool"`
    Timestamp   string `json:"timestamp"`
    Severity    string `json:"severity"`
    RuleID      string `json:"rule_id"`
    ClusterName string `json:"cluster_name"`
    Namespace   string `json:"namespace"`
    Resource    string `json:"resource"`
    Description string `json:"description"`
    Remediation string `json:"remediation"`
    AttackPath  string `json:"attack_path,omitempty"` // For graph findings
}
internal/report/wazuh_shipper.go
Your tool should write these JSON logs to a file (e.g., /var/log/k8s-hardener.log) that the Wazuh Agent monitors, OR send them directly to the Wazuh Manager via Syslog/Fluentbit.

Step 3.2: Wazuh Decoders
You need to teach Wazuh how to read your custom JSON. Add this to /var/ossec/etc/decoders/local_decoder.xml on the Wazuh Manager:

XML
<decoder name="k8s-hardener-json">
  <prematch>^{"tool":"k8s-hardener"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
Step 3.3: Wazuh Rules
Create custom rules to trigger alerts based on the severity of your findings. Add this to /var/ossec/etc/rules/local_rules.xml:

XML
<group name="k8s, security_hardener,">
  
  <rule id="110000" level="3">
    <decoded_as>k8s-hardener-json</decoded_as>
    <description>Kubernetes Security Hardener Event</description>
  </rule>

  <rule id="110001" level="10">
    <if_sid>110000</if_sid>
    <field name="severity">High</field>
    <description>K8s Hardener: High vulnerability in $(namespace)/$(resource) - $(description)</description>
    <mitre>
      <id>T1068</id> </mitre>
  </rule>

  <rule id="110002" level="12">
    <if_sid>110000</if_sid>
    <field name="severity">Critical</field>
    <match>AttackPath</match>
    <description>K8s Hardener: Critical Attack Path to ClusterAdmin detected in $(namespace)</description>
  </rule>

</group>
Step 3.4: Active Response (SOAR)
This is where you automate defense. If Wazuh detects a Critical runtime alert (e.g., via eBPF detecting a reverse shell in a pod), Wazuh can automatically isolate that pod.

1. Create a script on the Wazuh Agent (running on a K8s control plane or jump box):
/var/ossec/active-response/bin/k8s-isolate-pod.sh

Bash
#!/bin/bash
# Read Wazuh alert JSON from stdin
read ALERT
NAMESPACE=$(echo $ALERT | jq -r .parameters.alert.data.namespace)
POD=$(echo $ALERT | jq -r .parameters.alert.data.resource)

# Apply a NetworkPolicy to isolate the pod (Deny all ingress/egress)
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-compromised-pod
  namespace: $NAMESPACE
spec:
  podSelector:
    matchLabels:
      kubernetes.io/metadata.name: $POD
  policyTypes:
  - Ingress
  - Egress
EOF
2. Configure Wazuh Manager to trigger this script (ossec.conf):

XML
<command>
  <name>k8s-isolate</name>
  <executable>k8s-isolate-pod.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>k8s-isolate</command>
  <location>local</location>
  <rules_id>110002</rules_id> 
</active-response>
4. Implementation Roadmap for You
Since you are building this, here is the recommended order of operations to avoid feeling overwhelmed:

Phase 1: The Core Foundation (Weeks 1-2)

Initialize the Go project.

Build the client-go authentication.

Write the static scanners for RBAC and Pod Workloads.

Output standard JSON.

Phase 2: Wazuh Integration (Week 3)

Set up a local Wazuh instance.

Write the Decoders and Rules.

Test shipping the JSON from your Go binary to Wazuh and verifying alerts appear in the dashboard.

Phase 3: Prevention & SOAR (Weeks 4-5)

Convert your static scanner logic into the ValidatingWebhookConfiguration to block bad deployments.

Write the Wazuh Active Response bash scripts to automate remediation.

Phase 4: Advanced Detection (Weeks 6+)

Implement gonum/graph for the Attack Path mapping.

Experiment with cilium/ebpf for runtime execution tracking.

Integrate Ollama for LLM-based YAML remediation generation.