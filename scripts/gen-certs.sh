#!/bin/bash
# =============================================================================
# gen-certs.sh — Generate Self-Signed TLS Certificates for the Webhook
# =============================================================================
# Generates a CA and a server certificate signed by that CA.
# The caBundle from ca.crt must be base64-encoded and placed in
# the ValidatingWebhookConfiguration's clientConfig.caBundle field.
#
# Usage:
#   ./scripts/gen-certs.sh
#   # Then run:
#   kubectl create secret tls k8s-hardener-webhook-tls \
#     --cert=certs/tls.crt --key=certs/tls.key -n security
#   # Fill in caBundle:
#   cat certs/ca.crt | base64 | tr -d '\n'
# =============================================================================

set -euo pipefail

CERTS_DIR="certs"
SERVICE_NAME="k8s-hardener-webhook"
NAMESPACE="security"
DAYS=3650

mkdir -p "$CERTS_DIR"

echo "[gen-certs] Generating CA key and certificate..."
openssl genrsa -out "$CERTS_DIR/ca.key" 4096
openssl req -x509 -new -nodes \
  -key "$CERTS_DIR/ca.key" \
  -sha256 \
  -days "$DAYS" \
  -out "$CERTS_DIR/ca.crt" \
  -subj "/CN=k8s-hardener-ca/O=k8s-hardener"

echo "[gen-certs] Generating server key..."
openssl genrsa -out "$CERTS_DIR/tls.key" 4096

echo "[gen-certs] Generating server CSR..."
openssl req -new \
  -key "$CERTS_DIR/tls.key" \
  -out "$CERTS_DIR/tls.csr" \
  -subj "/CN=${SERVICE_NAME}.${NAMESPACE}.svc/O=k8s-hardener"

# SAN extension for the K8s service DNS names
cat > "$CERTS_DIR/san.ext" <<EOF
[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

echo "[gen-certs] Signing server certificate with CA..."
openssl x509 -req \
  -in "$CERTS_DIR/tls.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERTS_DIR/tls.crt" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$CERTS_DIR/san.ext" \
  -extensions v3_req

echo ""
echo "[gen-certs] ✅ Certificates generated in ./$CERTS_DIR/"
echo ""
echo "Next steps:"
echo "  1. Create the TLS secret:"
echo "     kubectl create secret tls k8s-hardener-webhook-tls \\"
echo "       --cert=$CERTS_DIR/tls.crt --key=$CERTS_DIR/tls.key -n security"
echo ""
echo "  2. Get the caBundle value:"
echo "     cat $CERTS_DIR/ca.crt | base64 | tr -d '\\n'"
echo ""
echo "  3. Paste the caBundle into deployments/webhook-deployment.yaml"
echo "     under webhooks[0].clientConfig.caBundle"
