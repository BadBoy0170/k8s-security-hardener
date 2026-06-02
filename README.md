# K8s Security Hardener

<div align="center">

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.27+-326CE5?style=for-the-badge&logo=kubernetes)
![Linux](https://img.shields.io/badge/Linux-5.8%2B-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM%2FSOAR-005571?style=for-the-badge)
![eBPF](https://img.shields.io/badge/eBPF-Runtime%20Detection-FF6600?style=for-the-badge)
![LLM](https://img.shields.io/badge/Ollama-dolphin--llama3-black?style=for-the-badge)

**Enterprise Kubernetes Security Hardening Platform**  
Static scanning · Graph attack-path analysis · eBPF runtime detection · LLM auto-remediation · SIEM integration

</div>

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    K8s API Server                               │
│                         │                                       │
│           ┌─────────────▼──────────────┐                        │
│           │  Admission Webhook         │  Blocks bad deploys    │
│           │  cmd/webhook               │  before they land      │
│           └─────────────┬──────────────┘                        │
└─────────────────────────┼───────────────────────────────────────┘
                          │
          ┌───────────────▼────────────────────┐
          │         Scanner Engine             │
          │  ┌─────────┐  ┌─────────────────┐  │
          │  │  RBAC   │  │   Workloads     │  │
          │  │ Scanner │  │   Scanner       │  │
          │  ├─────────┤  ├─────────────────┤  │
          │  │ Secrets │  │ Network Policy  │  │
          │  │ Scanner │  │   Scanner       │  │
          │  └─────────┘  └─────────────────┘  │
          │                                    │
          │  ┌──────────────┐  ┌─────────────┐ │
          │  │ Graph Attack │  │eBPF Runtime │ │
          │  │ Path (gonum) │  │  Monitor    │ │
          │  └──────────────┘  └─────────────┘ │
          │                                    │
          │  ┌──────────────────────────────┐  │
          │  │  LLM Auto-Remediation        │  │
          │  │  (Ollama / dolphin-llama3)   │  │
          │  └──────────────────────────────┘  │
          └───────────────┬────────────────────┘
                          │ JSON findings
          ┌───────────────▼────────────────────┐
          │              Wazuh                 │
          │ Decoders → Rules → Active Response │
          │ Pod isolation on Critical alerts   │
          └────────────────────────────────────┘
```

---

## Project Structure

```
k8s-security-hardener/
├── cmd/
│   ├── scanner/main.go              # CLI / CronJob entrypoint
│   └── webhook/main.go              # Admission controller entrypoint
├── internal/
│   ├── auth/client.go               # K8s API authentication (in-cluster + kubeconfig)
│   ├── scanners/
│   │   ├── rbac.go                  # Wildcard permissions, exec access checks
│   │   ├── workloads.go             # Privileged containers, root UID, missing limits
│   │   ├── secrets.go               # Hardcoded secrets in env vars
│   │   └── network.go               # Missing default-deny NetworkPolicies
│   ├── graph/attack_path.go         # Dijkstra's attack-path analysis (gonum)
│   ├── ebpf/
│   │   ├── runtime.go               # Linux eBPF monitor (sys_enter_execve)
│   │   ├── runtime_stub.go          # macOS no-op stub
│   │   └── bpf_linux_stub.go        # Linux type stubs (pre-bpf2go)
│   ├── remediation/llm_patcher.go   # Ollama LLM YAML patching
│   ├── webhook/validator.go         # ValidatingWebhookConfiguration handler
│   └── report/
│       ├── models.go                # SecurityFinding JSON schema
│       ├── wazuh_shipper.go         # File + syslog shipping to Wazuh
│       └── console.go               # Color-coded terminal output
├── deployments/
│   ├── scanner-cronjob.yaml         # CronJob + least-privilege ClusterRole
│   ├── webhook-deployment.yaml      # Webhook Deployment + ValidatingWebhookConfiguration
│   ├── wazuh/
│   │   ├── local_decoder.xml        # Wazuh JSON decoder
│   │   ├── local_rules.xml          # Alert rules 110000–110005 (MITRE ATT&CK mapped)
│   │   └── ossec-active-response.xml
│   └── wazuh-active-response.sh     # Pod isolation script for Wazuh agent
├── scripts/
│   └── gen-certs.sh                 # Self-signed TLS certificate generation
└── go.mod
```

---

## Quick Start

### Prerequisites

- Go 1.22+
- `kubectl` configured against a cluster (`kind`, `minikube`, or remote)
- (Optional) [Ollama](https://ollama.ai) for LLM auto-remediation
- (Optional) Linux 5.8+ kernel with BTF for eBPF runtime monitoring

### Build

```bash
go mod tidy

go build -o bin/scanner ./cmd/scanner
go build -o bin/webhook ./cmd/webhook
```

### Run Against Your Cluster

```bash
# Console output only — no changes made to the cluster
./bin/scanner --cluster-name=my-cluster --dry-run
```

### Ship Findings to Wazuh

```bash
./bin/scanner \
  --cluster-name=production \
  --output-file=/var/log/k8s-hardener.log \
  --syslog-addr=wazuh-manager:514
```

### LLM Auto-Remediation

```bash
# Default model: dolphin-llama3 (change with --ollama-model)
ollama serve
./bin/scanner --cluster-name=production --llm-fix --dry-run

# Test LLM without a cluster
./bin/scanner --mock-scan --llm-fix --ollama-model=dolphin-llama3
```

---

## 🔍 Security Checks

### RBAC Scanner

| Rule ID | Severity | Description |
|---|---|---|
| `RBAC-001` | Critical | ClusterRole with wildcard verbs **and** resources |
| `RBAC-002` | High | Role grants `pods/exec` or `pods/portforward` |
| `RBAC-003` | Critical | Subject bound to a wildcard ClusterRole |
| `RBAC-004` | High | Namespace-scoped Role with wildcard permissions |

### Workload Scanner

| Rule ID | Severity | Description |
|---|---|---|
| `WORKLOAD-001` | High | Pod `runAsUser: 0` (root) |
| `WORKLOAD-002` | Critical | Container `privileged: true` |
| `WORKLOAD-003` | High | Container `runAsUser: 0` |
| `WORKLOAD-004` | Medium | Missing `readOnlyRootFilesystem` |
| `WORKLOAD-005` | Medium | `allowPrivilegeEscalation` not set to `false` |
| `WORKLOAD-006` | Medium | No resource limits (CPU/memory) |
| `WORKLOAD-007` | High | `hostNetwork: true` |
| `WORKLOAD-008` | High | `hostPID: true` |

### Secrets Scanner

| Rule ID | Severity | Description |
|---|---|---|
| `SECRET-001` | High | Hardcoded credential in an environment variable |
| `SECRET-002` | Medium | Secret stored in the `default` namespace |
| `SECRET-003` | Low | Secret key with a sensitive name — audit access |

### Network Scanner

| Rule ID | Severity | Description |
|---|---|---|
| `NETWORK-001` | High | Namespace missing a default-deny **Ingress** NetworkPolicy |
| `NETWORK-002` | Medium | Namespace missing a default-deny **Egress** NetworkPolicy |

### Graph Attack-Path Analysis (`GRAPH-001`)

Builds a directed graph of Pods → ServiceAccounts → Secrets → Roles using `gonum/graph` and runs **Dijkstra's shortest path** to find exploitable routes from public-facing pods to ClusterAdmin-bound service accounts. Findings include the full path in `attack_path`.

### eBPF Runtime Monitor (`EBPF-001`)

Hooks into the `sys_enter_execve` kernel tracepoint and alerts when a container unexpectedly executes suspicious binaries (`bash`, `curl`, `nc`, `socat`, etc.).

> **Linux only** — requires kernel 5.8+ with BTF. On other platforms the stub runs silently. To enable full eBPF: install `clang` + `linux-headers`, write `bpf/execve_monitor.c`, then run `go generate ./internal/ebpf/`.

---

## Wazuh Integration

### Install Decoder and Rules

```bash
sudo cp deployments/wazuh/local_decoder.xml /var/ossec/etc/decoders/
sudo cp deployments/wazuh/local_rules.xml    /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

### Install Active Response Script

```bash
sudo cp deployments/wazuh-active-response.sh \
    /var/ossec/active-response/bin/k8s-isolate-pod.sh
sudo chmod 750  /var/ossec/active-response/bin/k8s-isolate-pod.sh
sudo chown root:wazuh /var/ossec/active-response/bin/k8s-isolate-pod.sh
```

Add the active-response wiring from `deployments/wazuh/ossec-active-response.xml` to `/var/ossec/etc/ossec.conf`.

### Alert Rules

| Rule ID | Level | Trigger |
|---|---|---|
| `110000` | 3  | Any k8s-hardener event |
| `110001` | 7  | Medium severity finding |
| `110002` | 10 | High severity finding |
| `110003` | 12 | Critical severity finding |
| `110004` | 14 | Critical + confirmed attack path |
| `110005` | 15 | eBPF runtime threat (reverse shell / suspicious exec) |

Rules **110004** and **110005** automatically trigger the Active Response script, which applies a deny-all NetworkPolicy to isolate the affected pod.

---

## Admission Controller

Blocks non-compliant workloads before they reach the cluster.

```bash
# Generate self-signed TLS certificates
./scripts/gen-certs.sh

# Create the TLS secret
kubectl create namespace security
kubectl create secret tls k8s-hardener-webhook-tls \
  --cert=certs/tls.crt --key=certs/tls.key -n security

# Fill in caBundle in webhook-deployment.yaml
CA_BUNDLE=$(cat certs/ca.crt | base64 | tr -d '\n')
# Paste $CA_BUNDLE into the caBundle field in deployments/webhook-deployment.yaml

# Deploy
kubectl apply -f deployments/webhook-deployment.yaml

# Verify — this should be rejected:
kubectl run bad-pod --image=nginx \
  --overrides='{"spec":{"containers":[{"name":"bad-pod","image":"nginx","securityContext":{"privileged":true}}]}}'
```

---

## LLM Remediation

Sends the raw YAML of a vulnerable resource to a local [Ollama](https://ollama.ai) model, which produces a hardened patch. The output is validated with `kubectl apply --dry-run=client` (falls back to structural YAML parse when no cluster is available).

```bash
# Pull the model (first time only)
ollama pull dolphin-llama3

# Run — LLM patches are appended to each finding's remediation field
./bin/scanner --llm-fix --ollama-model=dolphin-llama3 --cluster-name=production
```

Supported via `--ollama-model`: `dolphin-llama3`, `llama3`, `codellama`, or any model served by Ollama.

---

## Finding JSON Schema

All findings are emitted as newline-delimited JSON, compatible with Wazuh's `JSON_Decoder`:

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

## Security Notes

- **Read-only scanner** — the scanner ClusterRole only has `get` and `list` verbs; it never mutates cluster state
- **Fail-open webhook** — `failurePolicy: Ignore` keeps the cluster operational if the webhook is temporarily unavailable; change to `Fail` once the webhook has proven stability
- **Secure log file** — findings log is written with mode `0640` (owner + wazuh group only)
- **Hardened containers** — all provided manifests enforce `runAsNonRoot`, `readOnlyRootFilesystem`, and `capabilities.drop: ALL`
- **No hardcoded secrets** — all sensitive values are passed via flags or environment variables; `certs/` and `bin/` are gitignored

---

## Linux Compatibility

Everything works on Linux without code changes:

| Feature | Linux |
|---|---|
| All static scanners | ✅ Full |
| Graph attack-path analysis | ✅ Full |
| LLM remediation | ✅ Full (needs `ollama serve`) |
| Admission webhook | ✅ Full (needs TLS certs) |
| Wazuh integration | ✅ Full (needs `jq` + Wazuh agent) |
| eBPF runtime monitor | ✅ Compiles; needs `go generate` + `clang` for live bytecode |

---

