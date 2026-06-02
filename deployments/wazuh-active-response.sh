#!/bin/bash
# =============================================================================
# k8s-isolate-pod.sh — Wazuh Active Response Script
# =============================================================================
# Install location: /var/ossec/active-response/bin/k8s-isolate-pod.sh
# Permissions:      chmod 750 /var/ossec/active-response/bin/k8s-isolate-pod.sh
#                   chown root:wazuh /var/ossec/active-response/bin/k8s-isolate-pod.sh
#
# Description:
#   Triggered by Wazuh when a Critical alert fires (rule 110004 or 110005).
#   Reads the alert JSON from stdin, extracts the pod namespace and name,
#   then applies a deny-all NetworkPolicy to isolate the compromised pod.
#
# Requirements:
#   - kubectl configured with cluster access (kubeconfig or in-cluster)
#   - jq installed on the Wazuh agent host
#   - Sufficient RBAC to apply NetworkPolicies in the target namespace
# =============================================================================

set -euo pipefail

LOG_FILE="/var/ossec/logs/k8s-active-response.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log() {
    echo "${TIMESTAMP} [k8s-isolate] $*" | tee -a "$LOG_FILE"
}

log "=== Active Response triggered ==="

# Read the full Wazuh alert JSON from stdin
read -r ALERT_JSON

log "Raw alert received: $ALERT_JSON"

# Extract namespace and resource from the alert data
NAMESPACE=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.data.namespace // empty')
RESOURCE=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.data.resource // empty')
SEVERITY=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.data.severity // "Unknown"')
RULE_ID=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.data.rule_id // "Unknown"')

# resource may be "pod/my-pod-abc123" or "container/abc123 (pid 12345)"
# Strip "pod/" prefix if present
POD_NAME=$(echo "$RESOURCE" | sed 's|pod/||' | cut -d' ' -f1)

if [[ -z "$NAMESPACE" || -z "$POD_NAME" ]]; then
    log "ERROR: Could not extract namespace or pod name from alert. Aborting."
    log "  namespace='$NAMESPACE' resource='$RESOURCE'"
    exit 1
fi

log "Isolating pod: namespace=$NAMESPACE pod=$POD_NAME severity=$SEVERITY rule=$RULE_ID"

# Verify the pod exists before applying the NetworkPolicy
if ! kubectl get pod "$POD_NAME" -n "$NAMESPACE" &>/dev/null; then
    log "WARNING: Pod $POD_NAME not found in namespace $NAMESPACE — it may have already been deleted."
    exit 0
fi

# Apply a deny-all-ingress-egress NetworkPolicy targeting this specific pod
# The pod must have a label we can match. We use 'kubernetes.io/metadata.name' 
# which is automatically added to namespaces, but for pods we use the pod name label.
# If your pods don't have a name label, consider using a LabelSelector on 'pod-name'.

POLICY_NAME="isolate-compromised-$(echo "$POD_NAME" | tr '[:upper:]' '[:lower:]' | cut -c1-40)"

kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${POLICY_NAME}
  namespace: ${NAMESPACE}
  labels:
    managed-by: wazuh-active-response
    isolated-pod: "${POD_NAME}"
    isolation-reason: "${RULE_ID}"
    isolated-at: "$(date -u +%Y%m%dT%H%M%SZ)"
spec:
  podSelector:
    matchLabels:
      app: "${POD_NAME}"
  policyTypes:
  - Ingress
  - Egress
EOF

APPLY_EXIT=$?

if [[ $APPLY_EXIT -eq 0 ]]; then
    log "SUCCESS: NetworkPolicy '$POLICY_NAME' applied — pod $NAMESPACE/$POD_NAME is now isolated."
    log "  To un-isolate: kubectl delete networkpolicy $POLICY_NAME -n $NAMESPACE"
else
    log "ERROR: Failed to apply NetworkPolicy (exit code: $APPLY_EXIT)"
    
    # Fallback: try to delete the pod directly
    log "Attempting fallback: deleting pod $NAMESPACE/$POD_NAME"
    if kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --grace-period=0 --force; then
        log "SUCCESS: Pod $NAMESPACE/$POD_NAME force-deleted as fallback isolation."
    else
        log "ERROR: Fallback pod deletion also failed. Manual intervention required."
        exit 1
    fi
fi

log "=== Active Response complete ==="
