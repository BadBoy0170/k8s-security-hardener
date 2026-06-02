package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/badboy0170/k8s-sec-hardener/internal/auth"
	"github.com/badboy0170/k8s-sec-hardener/internal/graph"
	"github.com/badboy0170/k8s-sec-hardener/internal/remediation"
	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	"github.com/badboy0170/k8s-sec-hardener/internal/scanners"
)

func main() {
	var (
		outputFile  = flag.String("output-file", "", "Path to write JSON findings (e.g. /var/log/k8s-hardener.log)")
		syslogAddr  = flag.String("syslog-addr", "", "Wazuh syslog address host:port (e.g. wazuh-manager:514)")
		clusterName = flag.String("cluster-name", "default", "Logical cluster name included in every finding")
		dryRun      = flag.Bool("dry-run", false, "Print findings to stdout only, do not ship to Wazuh")
		llmFix      = flag.Bool("llm-fix", false, "Generate LLM-based YAML patches for workload findings")
		ollamaURL   = flag.String("ollama-url", "http://localhost:11434", "Ollama API base URL")
		ollamaModel = flag.String("ollama-model", "dolphin-llama3", "Ollama model to use for remediation")
		mockScan    = flag.Bool("mock-scan", false, "Inject synthetic findings for local testing without a real K8s cluster (macOS dev mode)")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Printf("[k8s-hardener] Starting scan on cluster: %s", *clusterName)

	// --- Mock mode for macOS / no-cluster testing ---
	if *mockScan {
		log.Println("[k8s-hardener] MOCK MODE: injecting synthetic findings for local testing")
		allFindings := mockFindings(*clusterName)
		report.PrintConsole(allFindings)
		if *llmFix {
			patcher := remediation.NewLLMPatcher(*ollamaURL, *ollamaModel)
			log.Printf("[k8s-hardener] Testing LLM connection to %s (model: %s)...", *ollamaURL, *ollamaModel)
			for i, f := range allFindings {
				if f.RuleID == "WORKLOAD-002" {
					patch, err := patcher.PatchFinding(ctx, f)
					if err != nil {
						log.Printf("[k8s-hardener] LLM test error: %v", err)
					} else {
						log.Printf("[k8s-hardener] LLM test OK — patch for %s:\n%s", f.Resource, patch)
						allFindings[i].Remediation = "LLM patch:\n" + patch
					}
					break // test one finding only
				}
			}
		}
		os.Exit(0)
	}

	clientset, err := auth.BuildClient()
	if err != nil {
		log.Fatalf("[k8s-hardener] Failed to connect to Kubernetes: %v", err)
	}

	var allFindings []report.SecurityFinding

	// --- Run all static scanners ---
	runScanner := func(name string, fn func() ([]report.SecurityFinding, error)) {
		log.Printf("[k8s-hardener] Running %s scanner...", name)
		findings, err := fn()
		if err != nil {
			log.Printf("[k8s-hardener] WARN: %s scanner error: %v", name, err)
			return
		}
		log.Printf("[k8s-hardener] %s scanner: %d findings", name, len(findings))
		allFindings = append(allFindings, findings...)
	}

	runScanner("RBAC", func() ([]report.SecurityFinding, error) {
		return scanners.ScanRBAC(ctx, clientset, *clusterName)
	})
	runScanner("Workloads", func() ([]report.SecurityFinding, error) {
		return scanners.ScanWorkloads(ctx, clientset, *clusterName)
	})
	runScanner("Secrets", func() ([]report.SecurityFinding, error) {
		return scanners.ScanSecrets(ctx, clientset, *clusterName)
	})
	runScanner("Network", func() ([]report.SecurityFinding, error) {
		return scanners.ScanNetwork(ctx, clientset, *clusterName)
	})

	// --- Graph-based attack path analysis ---
	log.Println("[k8s-hardener] Running graph-based attack path analysis...")
	graphFindings, err := graph.FindAttackPaths(ctx, clientset, *clusterName)
	if err != nil {
		log.Printf("[k8s-hardener] WARN: Attack path analysis error: %v", err)
	} else {
		log.Printf("[k8s-hardener] Attack path analysis: %d critical paths found", len(graphFindings))
		allFindings = append(allFindings, graphFindings...)
	}

	// --- Optional LLM-based remediation ---
	if *llmFix {
		patcher := remediation.NewLLMPatcher(*ollamaURL, *ollamaModel)
		log.Printf("[k8s-hardener] Generating LLM patches (model: %s)...", *ollamaModel)
		for i, f := range allFindings {
			if f.RuleID == "WORKLOAD-002" || f.RuleID == "WORKLOAD-001" {
				patch, err := patcher.PatchFinding(ctx, f)
				if err != nil {
					log.Printf("[k8s-hardener] LLM patch failed for %s: %v", f.Resource, err)
					continue
				}
				allFindings[i].Remediation = fmt.Sprintf("%s\n\nLLM Patch:\n%s", f.Remediation, patch)
			}
		}
	}

	// --- Output ---
	report.PrintConsole(allFindings)

	if *dryRun {
		log.Println("[k8s-hardener] Dry-run mode: skipping Wazuh shipping.")
		os.Exit(0)
	}

	if *outputFile != "" {
		if err := report.ShipToFile(allFindings, *outputFile); err != nil {
			log.Printf("[k8s-hardener] Failed to write to file %q: %v", *outputFile, err)
		} else {
			log.Printf("[k8s-hardener] Findings written to %s", *outputFile)
		}
	}

	if *syslogAddr != "" {
		if err := report.ShipToSyslog(allFindings, *syslogAddr); err != nil {
			log.Printf("[k8s-hardener] Failed to ship to syslog %q: %v", *syslogAddr, err)
		} else {
			log.Printf("[k8s-hardener] Findings shipped to syslog at %s", *syslogAddr)
		}
	}

	// Exit with non-zero code if critical findings exist
	for _, f := range allFindings {
		if f.Severity == report.SeverityCritical {
			os.Exit(2)
		}
	}
}

// mockFindings returns a realistic set of synthetic findings for local testing on macOS
// without needing a real Kubernetes cluster. Covers all rule categories.
func mockFindings(clusterName string) []report.SecurityFinding {
	ts := time.Now().UTC().Format(time.RFC3339)
	return []report.SecurityFinding{
		{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityCritical,
			RuleID:      "RBAC-001",
			ClusterName: clusterName,
			Namespace:   "cluster-scoped",
			Resource:    "clusterrole/super-admin",
			Description: "[MOCK] ClusterRole has wildcard verbs and resources — grants full cluster access",
			Remediation: "Remove wildcard rules and apply least-privilege permissions.",
		},
		{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityCritical,
			RuleID:      "WORKLOAD-002",
			ClusterName: clusterName,
			Namespace:   "default",
			Resource:    "deployment/nginx-test/container/nginx",
			Description: "[MOCK] Container is running in privileged mode — has full host access",
			Remediation: "Set securityContext.privileged: false. Use specific capabilities if needed.",
		},
		{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityHigh,
			RuleID:      "RBAC-002",
			ClusterName: clusterName,
			Namespace:   "cluster-scoped",
			Resource:    "clusterrole/devops-role",
			Description: "[MOCK] ClusterRole grants pods/exec — allows interactive shell access to any pod",
			Remediation: "Remove pods/exec and pods/portforward sub-resource permissions.",
		},
		{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityHigh,
			RuleID:      "NETWORK-001",
			ClusterName: clusterName,
			Namespace:   "production",
			Resource:    "namespace/production",
			Description: "[MOCK] Namespace has no default-deny Ingress NetworkPolicy",
			Remediation: "Apply a default-deny ingress NetworkPolicy.",
		},
		{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityHigh,
			RuleID:      "SECRET-001",
			ClusterName: clusterName,
			Namespace:   "default",
			Resource:    "deployment/api-server/container/app",
			Description: "[MOCK] Environment variable 'DATABASE_PASSWORD' contains a hardcoded value",
			Remediation: "Replace with secretKeyRef or use an external secrets operator.",
		},
		{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityMedium,
			RuleID:      "WORKLOAD-006",
			ClusterName: clusterName,
			Namespace:   "staging",
			Resource:    "deployment/frontend/container/app",
			Description: "[MOCK] Container has no resource limits — risk of resource exhaustion",
			Remediation: "Set resources.limits.cpu and resources.limits.memory.",
		},
		{
			Tool:        report.ToolName,
			Timestamp:   ts,
			Severity:    report.SeverityCritical,
			RuleID:      "GRAPH-001",
			ClusterName: clusterName,
			Namespace:   "default",
			Resource:    "pod/web-frontend-abc123",
			Description: "[MOCK] Attack path: public-facing pod can reach ClusterAdmin ServiceAccount 'kube-system/default'",
			Remediation: "Remove ClusterAdmin binding. Apply NetworkPolicies. Use least-privilege service accounts.",
			AttackPath:  "Pod/default/web-frontend-abc123 → ServiceAccount/default/default → ClusterRole/cluster-admin",
		},
	}
}

