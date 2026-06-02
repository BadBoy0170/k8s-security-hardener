package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/badboy0170/k8s-sec-hardener/internal/report"
	"github.com/badboy0170/k8s-sec-hardener/internal/scanners"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
)

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

// Validator is the core admission webhook handler.
// It decodes incoming AdmissionReview requests, runs security checks,
// and returns allow/deny decisions with detailed violation messages.
type Validator struct {
	clusterName string
}

// NewValidator creates a new Validator for the given cluster.
func NewValidator(clusterName string) *Validator {
	return &Validator{clusterName: clusterName}
}

// ServeHTTP handles POST /validate requests from the K8s API server.
func (v *Validator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if _, _, err := universalDeserializer.Decode(body, nil, &review); err != nil {
		// Fall back to JSON decode if the universal deserializer fails
		if err2 := json.Unmarshal(body, &review); err2 != nil {
			http.Error(w, fmt.Sprintf("could not decode admission review: %v", err), http.StatusBadRequest)
			return
		}
	}

	if review.Request == nil {
		http.Error(w, "nil admission request", http.StatusBadRequest)
		return
	}

	response := v.validate(review.Request)
	review.Response = response
	review.Response.UID = review.Request.UID

	resp, err := json.Marshal(review)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(resp); err != nil {
		log.Printf("[webhook] failed to write response: %v", err)
	}
}

// validate inspects the incoming object and returns an AdmissionResponse.
func (v *Validator) validate(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	log.Printf("[webhook] Validating %s/%s in namespace %q", req.Kind.Kind, req.Name, req.Namespace)

	podSpec, err := extractPodSpec(req)
	if err != nil {
		// Cannot extract — allow with warning (fail-open for unsupported resource types)
		log.Printf("[webhook] Could not extract pod spec: %v — allowing", err)
		return allowed("", req.UID)
	}

	// Run the workload scanner against the incoming pod spec
	findings := scanners.AuditPodSpecDirect(podSpec, req.Kind.Kind+"/"+req.Name, req.Namespace, v.clusterName)

	// Filter to High and Critical only — don't block on Medium/Low
	var violations []report.SecurityFinding
	for _, f := range findings {
		if f.Severity == report.SeverityCritical || f.Severity == report.SeverityHigh {
			violations = append(violations, f)
		}
	}

	if len(violations) == 0 {
		return allowed("", req.UID)
	}

	// Build rejection message
	msg := buildRejectionMessage(violations)
	log.Printf("[webhook] Rejected %s/%s: %d violation(s)", req.Kind.Kind, req.Name, len(violations))
	return denied(msg, req.UID)
}

// extractPodSpec extracts the PodSpec from Deployment, DaemonSet, StatefulSet, or Pod objects.
func extractPodSpec(req *admissionv1.AdmissionRequest) (corev1.PodSpec, error) {
	switch req.Kind.Kind {
	case "Deployment":
		var dep appsv1.Deployment
		if err := json.Unmarshal(req.Object.Raw, &dep); err != nil {
			return corev1.PodSpec{}, err
		}
		return dep.Spec.Template.Spec, nil

	case "DaemonSet":
		var ds appsv1.DaemonSet
		if err := json.Unmarshal(req.Object.Raw, &ds); err != nil {
			return corev1.PodSpec{}, err
		}
		return ds.Spec.Template.Spec, nil

	case "StatefulSet":
		var ss appsv1.StatefulSet
		if err := json.Unmarshal(req.Object.Raw, &ss); err != nil {
			return corev1.PodSpec{}, err
		}
		return ss.Spec.Template.Spec, nil

	case "Pod":
		var pod corev1.Pod
		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			return corev1.PodSpec{}, err
		}
		return pod.Spec, nil

	default:
		return corev1.PodSpec{}, fmt.Errorf("unsupported kind: %s", req.Kind.Kind)
	}
}

// buildRejectionMessage creates a human-readable rejection message from violations.
func buildRejectionMessage(violations []report.SecurityFinding) string {
	msg := fmt.Sprintf("❌ Rejected by k8s-security-hardener: %d security violation(s) found:\n\n", len(violations))
	for i, v := range violations {
		msg += fmt.Sprintf("  %d. [%s] %s — %s\n     Fix: %s\n\n",
			i+1, v.Severity, v.RuleID, v.Description, v.Remediation)
	}
	msg += "See docs: https://github.com/badboy0170/k8s-sec-hardener"
	return msg
}

func allowed(msg string, uid types.UID) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     uid,
		Allowed: true,
		Result:  &metav1.Status{Message: msg},
	}
}

func denied(msg string, uid types.UID) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     uid,
		Allowed: false,
		Result: &metav1.Status{
			Code:    http.StatusForbidden,
			Message: msg,
		},
	}
}
