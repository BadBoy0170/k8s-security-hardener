# K8s Security Hardener

<div align="center">

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.27+-326CE5?style=for-the-badge&logo=kubernetes)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM%2FSOAR-005571?style=for-the-badge)
![eBPF](https://img.shields.io/badge/eBPF-Runtime%20Detection-FF6600?style=for-the-badge)
![LLM](https://img.shields.io/badge/Ollama-LLM%20Remediation-black?style=for-the-badge)

**Enterprise Kubernetes Security Hardening Platform**  
Static scanning · Graph attack-path analysis · eBPF runtime detection · LLM auto-remediation · SIEM integration

</div>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    K8s API Server                               │
│                         │                                       │
│           ┌─────────────▼──────────────┐                        │
│           │  Admission Webhook         │                        │
│           │  cmd/webhook               │  Blocks bad deploys    │
│           └─────────────┬──────────────┘                        │
└─────────────────────────┼───────────────────────────────────────┘
                          │
          ┌───────────────▼────────────────────┐
          │         Scanner Engine             │
          │  ┌─────────┐  ┌─────────────────┐  │
          │  │ RBAC    │  │ Workloads       │  │  
          │  │ Scanner │  │ Scanner         │  │
          │  ├─────────┤  ├─────────────────┤  │
          │  │ Secrets │  │ Network Policy  │  │
          │  │ Scanner │  │ Scanner         │  │
          │  └─────────┘  └─────────────────┘  │
          │                                    │
          │  ┌──────────────┐  ┌─────────────┐ │
          │  │ Graph Attack │  │ eBPF Runtime│ │  
          │  │ Path (gonum) │  │ Monitor     │ │
          │  └──────────────┘  └─────────────┘ │
          │                                    │
          │  ┌──────────────────────────────┐  │
          │  │  LLM Auto-Remediation        │  │
          │  │  (Ollama / llama3)           │  │
          │  └──────────────────────────────┘  │
          └───────────────┬────────────────────┘
                          │ JSON findings
          ┌───────────────▼────────────────────┐
          │              Wazuh                 │  
          │ Decoders → Rules → Active Response │
          │ Pod isolation on Critical alerts   │
          └────────────────────────────────────┘
```

## 📁 Project Structure

```
k8s-security-hardener/
├── cmd/
│   ├── scanner/main.go           # CLI / CronJob entrypoint
│   └── webhook/main.go           # Admission controller entrypoint
├── internal/
│   ├── auth/client.go            # K8s API authentication
│   ├── scanners/
│   │   ├── rbac.go               # RBAC wildcard / exec access checks
│   │   ├── workloads.go          # Privileged, root, missing limits
│   │   ├── secrets.go            # Exposed/hardcoded secrets
│   │   └── network.go            # Missing NetworkPolicy checks
│   ├── graph/attack_path.go      # Dijkstra's attack path analysis
│   ├── ebpf/
│   │   ├── runtime.go            # Linux eBPF monitor (sys_enter_execve)
│   │   └── runtime_stub.go       # macOS/Windows no-op stub
│   ├── remediation/llm_patcher.go # Ollama LLM YAML patching
│   ├── webhook/validator.go      # ValidatingWebhookConfiguration handler
│   └── report/
│       ├── models.go             # SecurityFinding schema
│       ├── wazuh_shipper.go      # File + syslog log shipping
│       └── console.go            # Color-coded CLI output
├── deployments/
│   ├── scanner-cronjob.yaml      # Scanner CronJob + RBAC
│   ├── webhook-deployment.yaml   # Webhook Deployment + VWC
│   └── wazuh/
│       ├── local_decoder.xml     # Wazuh JSON decoder
│       ├── local_rules.xml       # Wazuh alert rules (110000-110005)
│       └── ossec-active-response.xml  # Active Response wiring
│   └── wazuh-active-response.sh  # Pod isolation script for Wazuh agent
├── scripts/
│   └── gen-certs.sh              # Self-signed TLS cert generation
└── go.mod
```

## 🚀 Quick Start

### Prerequisites
- Go 1.22+
- A Kubernetes cluster (local: `kind`, `minikube`, or remote)
- `kubectl` configured with cluster access
- (Optional) Ollama running locally for LLM features
- (Optional) Linux 5.8+ for eBPF runtime monitoring

### 1. Install Dependencies

```bash
cd k8s-security-hardener
go mod tidy
```

### 2. Build

```bash
# Build the scanner CLI
go build -o bin/scanner ./cmd/scanner

# Build the admission webhook
go build -o bin/webhook ./cmd/webhook
```

### 3. Run the Scanner (Dry-Run)

```bash
# Scan your current kubeconfig cluster, output to console only
./bin/scanner --cluster-name=my-cluster --dry-run
```

### 4. Run with Wazuh Log Shipping

```bash
./bin/scanner \
  --cluster-name=production \
  --output-file=/var/log/k8s-hardener.log \
  --syslog-addr=wazuh-manager:514
```

### 5. Enable LLM Auto-Remediation

```bash
# Make sure Ollama is running: ollama serve
./bin/scanner \
  --cluster-name=production \
  --dry-run \
  --llm-fix \
  --ollama-model=llama3
```

---

## 🔍 Scanners

### RBAC Scanner (`RBAC-001` to `RBAC-004`)
| Rule ID | Severity | Description |
|---|---|---|
| `RBAC-001` | Critical | ClusterRole with wildcard verbs AND resources |
| `RBAC-002` | High | Role grants `pods/exec` or `pods/portforward` |
| `RBAC-003` | Critical | Subject bound to wildcard ClusterRole |
| `RBAC-004` | High | Namespace Role with wildcard permissions |

### Workload Scanner (`WORKLOAD-001` to `WORKLOAD-008`)
| Rule ID | Severity | Description |
|---|---|---|
| `WORKLOAD-001` | High | Pod `runAsUser: 0` (root) |
| `WORKLOAD-002` | Critical | Container `privileged: true` |
| `WORKLOAD-003` | High | Container `runAsUser: 0` |
| `WORKLOAD-004` | Medium | Missing `readOnlyRootFilesystem` |
| `WORKLOAD-005` | Medium | `allowPrivilegeEscalation` not false |
| `WORKLOAD-006` | Medium | Missing resource limits |
| `WORKLOAD-007` | High | `hostNetwork: true` |
| `WORKLOAD-008` | High | `hostPID: true` |

### Graph Attack Path (`GRAPH-001`)
Uses **Dijkstra's shortest path** via `gonum/graph` to find exploitable paths from public-facing pods to ClusterAdmin service accounts.

### eBPF Runtime (`EBPF-001`)
Hooks into `sys_enter_execve` to detect anomalous binary execution inside containers (e.g., `bash`, `curl`, `nc` inside an Nginx container).

> **Note**: eBPF requires Linux kernel 5.8+ with BTF. macOS/Windows automatically use the stub (no-op) mode.

---

## 🔗 Wazuh Integration

### Setup

1. Copy decoder to Wazuh Manager:
```bash
sudo cp deployments/wazuh/local_decoder.xml /var/ossec/etc/decoders/
sudo cp deployments/wazuh/local_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

2. Install active response script on the agent:
```bash
sudo cp deployments/wazuh-active-response.sh /var/ossec/active-response/bin/k8s-isolate-pod.sh
sudo chmod 750 /var/ossec/active-response/bin/k8s-isolate-pod.sh
sudo chown root:wazuh /var/ossec/active-response/bin/k8s-isolate-pod.sh
```

3. Add active response wiring to `/var/ossec/etc/ossec.conf` (see `deployments/wazuh/ossec-active-response.xml`)

### Wazuh Rules
| Rule ID | Level | Trigger |
|---|---|---|
| `110000` | 3 | Any k8s-hardener event |
| `110001` | 7 | Medium severity finding |
| `110002` | 10 | High severity finding |
| `110003` | 12 | Critical severity finding |
| `110004` | 14 | Critical + Attack Path detected |
| `110005` | 15 | eBPF runtime threat detected |

Rules 110004 and 110005 trigger **automatic pod isolation** via the Active Response script.

---

## 🛡️ Admission Controller

The webhook blocks non-compliant deployments at the gate.

```bash
# Generate TLS certificates
./scripts/gen-certs.sh

# Create the TLS secret
kubectl create namespace security
kubectl create secret tls k8s-hardener-webhook-tls \
  --cert=certs/tls.crt --key=certs/tls.key -n security

# Get the caBundle and update webhook-deployment.yaml
CA_BUNDLE=$(cat certs/ca.crt | base64 | tr -d '\n')
# Paste $CA_BUNDLE into the caBundle field in webhook-deployment.yaml

# Deploy
kubectl apply -f deployments/webhook-deployment.yaml

# Test — this privileged pod should be rejected:
kubectl run test-priv --image=nginx --overrides='{"spec":{"containers":[{"name":"test-priv","image":"nginx","securityContext":{"privileged":true}}]}}'
```

---

## 🧠 LLM Remediation

Integrates with [Ollama](https://ollama.ai) to auto-generate hardened YAML patches:

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3

# Run with LLM patching enabled
./bin/scanner --llm-fix --ollama-model=llama3 --dry-run
```

The LLM output is validated with `kubectl apply --dry-run=client` before being suggested.

---

## 📊 Finding JSON Schema

Every finding is emitted as a JSON object:

```json
{
  "tool": "k8s-hardener",
  "timestamp": "2026-06-01T12:00:00Z",
  "severity": "Critical",
  "rule_id": "RBAC-001",
  "cluster_name": "production",
  "namespace": "default",
  "resource": "clusterrole/admin",
  "description": "ClusterRole has wildcard verbs and resources",
  "remediation": "Remove wildcard rules and apply least-privilege permissions.",
  "attack_path": "Pod/default/web → ServiceAccount/default/admin → ClusterRole/cluster-admin"
}
```
---

## 🔐 Security Notes

- The scanner runs with **read-only** RBAC permissions — it never modifies cluster state
- The webhook uses **fail-open** (`failurePolicy: Ignore`) by default — the cluster stays operational if the webhook is unreachable
- The eBPF monitor requires privileged access on Linux — it is only deployed in the CronJob on Linux nodes
- All containers in the manifests enforce `runAsNonRoot`, `readOnlyRootFilesystem`, and drop all capabilities

---

## 📜 License

MIT — see [LICENSE](LICENSE)
