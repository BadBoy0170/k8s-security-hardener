package graph

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	gonumgraph "gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/path"
	"gonum.org/v1/gonum/graph/simple"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NodeType classifies what a graph node represents.
type NodeType string

const (
	NodeTypePod            NodeType = "Pod"
	NodeTypeServiceAccount NodeType = "ServiceAccount"
	NodeTypeSecret         NodeType = "Secret"
	NodeTypeRole           NodeType = "Role"
)

// K8sNode is a vertex in the attack graph.
type K8sNode struct {
	id          int64
	Kind        NodeType
	Namespace   string
	Name        string
	IsPublicFacing bool   // true for pods exposed via LoadBalancer/NodePort
	IsClusterAdmin bool   // true for ClusterAdmin-bound service accounts
}

func (n K8sNode) ID() int64 { return n.id }

// FindAttackPaths builds a directed graph of K8s resources and uses Dijkstra's algorithm
// to find paths from public-facing pods to ClusterAdmin-bound service accounts.
// If any such path is found, it returns Critical findings with the full path annotated.
func FindAttackPaths(ctx context.Context, clientset kubernetes.Interface, clusterName string) ([]report.SecurityFinding, error) {
	g := simple.NewDirectedGraph()
	nodeMap := map[string]*K8sNode{} // key: "kind/namespace/name"
	var nextID int64

	newNode := func(kind NodeType, ns, name string) *K8sNode {
		key := fmt.Sprintf("%s/%s/%s", kind, ns, name)
		if existing, ok := nodeMap[key]; ok {
			return existing
		}
		n := &K8sNode{id: nextID, Kind: kind, Namespace: ns, Name: name}
		nextID++
		nodeMap[key] = n
		g.AddNode(n)
		return n
	}

	// --- Load Services to identify public-facing pods ---
	publicPodLabels := map[string]bool{} // namespace/labelKey=value
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}
	for _, svc := range services.Items {
		if svc.Spec.Type == "LoadBalancer" || svc.Spec.Type == "NodePort" {
			for k, v := range svc.Spec.Selector {
				publicPodLabels[fmt.Sprintf("%s/%s=%s", svc.Namespace, k, v)] = true
			}
		}
	}

	// --- Find ClusterAdmin-bound service accounts ---
	clusterAdminSAs := map[string]bool{} // namespace/name
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)
	}
	for _, crb := range crbs.Items {
		if crb.RoleRef.Name == "cluster-admin" {
			for _, subj := range crb.Subjects {
				if subj.Kind == "ServiceAccount" {
					clusterAdminSAs[fmt.Sprintf("%s/%s", subj.Namespace, subj.Name)] = true
				}
			}
		}
	}

	// --- Build graph: Pods → ServiceAccounts → Secrets ---
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	var publicNodes []*K8sNode
	var clusterAdminNodes []*K8sNode

	for _, pod := range pods.Items {
		podNode := newNode(NodeTypePod, pod.Namespace, pod.Name)

		// Check if pod is public-facing
		for k, v := range pod.Labels {
			if publicPodLabels[fmt.Sprintf("%s/%s=%s", pod.Namespace, k, v)] {
				podNode.IsPublicFacing = true
			}
		}
		if podNode.IsPublicFacing {
			publicNodes = append(publicNodes, podNode)
		}

		// Pod → ServiceAccount edge
		if pod.Spec.ServiceAccountName != "" {
			saNode := newNode(NodeTypeServiceAccount, pod.Namespace, pod.Spec.ServiceAccountName)
			saKey := fmt.Sprintf("%s/%s", pod.Namespace, pod.Spec.ServiceAccountName)
			if clusterAdminSAs[saKey] {
				saNode.IsClusterAdmin = true
				clusterAdminNodes = append(clusterAdminNodes, saNode)
			}
			g.SetEdge(g.NewEdge(podNode, saNode))
		}

		// Pod → Secrets (mounted volumes)
		for _, vol := range pod.Spec.Volumes {
			if vol.Secret != nil {
				secretNode := newNode(NodeTypeSecret, pod.Namespace, vol.Secret.SecretName)
				g.SetEdge(g.NewEdge(podNode, secretNode))
			}
		}
	}

	// --- Run Dijkstra's from each public-facing pod to each ClusterAdmin SA ---
	var findings []report.SecurityFinding

	for _, src := range publicNodes {
		allPaths := path.DijkstraFrom(src, g)
		for _, dst := range clusterAdminNodes {
			nodePath, _ := allPaths.To(dst.ID())
			if len(nodePath) > 0 {
				// Build human-readable path string
				pathStr := buildPathString(nodePath)
				findings = append(findings, report.SecurityFinding{
					Tool:        report.ToolName,
					Timestamp:   time.Now().UTC().Format(time.RFC3339),
					Severity:    report.SeverityCritical,
					RuleID:      "GRAPH-001",
					ClusterName: clusterName,
					Namespace:   src.Namespace,
					Resource:    fmt.Sprintf("pod/%s", src.Name),
					Description: fmt.Sprintf("Attack path discovered: public-facing pod can reach ClusterAdmin ServiceAccount '%s/%s'", dst.Namespace, dst.Name),
					Remediation: "Remove ClusterAdmin binding from the ServiceAccount. Apply NetworkPolicies to restrict pod-to-pod communication. Use least-privilege service accounts.",
					AttackPath:  pathStr,
				})
			}
		}
	}

	return findings, nil
}

// buildPathString converts a graph node path to a human-readable arrow-separated string.
func buildPathString(nodes []gonumgraph.Node) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if kn, ok := n.(*K8sNode); ok {
			parts = append(parts, fmt.Sprintf("%s/%s/%s", kn.Kind, kn.Namespace, kn.Name))
		}
	}
	return strings.Join(parts, " → ")
}
