#!/usr/bin/env bash
# Refresh the pinned Proton Bridge certificate that Comlink verifies against.
#
# Comlink connects to the in-cluster Bridge over TLS in `verify-no-hostname`
# mode, pinning Bridge's self-signed cert via the `bridge-cert` ConfigMap. If
# you ever re-auth or reinstall Bridge, it regenerates that cert and the pin no
# longer matches — IMAP TLS then fails. Run this script AFTER any such Bridge
# change: it re-extracts the cert Bridge currently presents, validates it,
# updates the ConfigMap, and rolls Comlink so it re-reads the new cert.
#
# Safe by design: it validates the freshly-extracted cert BEFORE touching the
# ConfigMap, so a failed extraction never clobbers a working pin.
#
# Usage:
#   bash deploy/refresh-bridge-cert.sh
# Overridable via env (defaults shown):
#   COMLINK_NS=comlink  COMLINK_DEPLOY=comlink
#   BRIDGE_NS=proton-bridge  BRIDGE_SVC=proton-bridge  BRIDGE_IMAP_PORT=1143
set -euo pipefail

NS="${COMLINK_NS:-comlink}"
DEPLOY="${COMLINK_DEPLOY:-comlink}"
BRIDGE_NS="${BRIDGE_NS:-proton-bridge}"
BRIDGE_SVC="${BRIDGE_SVC:-proton-bridge}"
BRIDGE_IMAP_PORT="${BRIDGE_IMAP_PORT:-1143}"
BRIDGE_HOST="${BRIDGE_SVC}.${BRIDGE_NS}.svc.cluster.local"

CERT_FILE="$(mktemp)"
trap 'rm -f "$CERT_FILE"; kubectl delete pod certrefresh --ignore-not-found >/dev/null 2>&1 || true' EXIT

echo ">> Extracting cert from ${BRIDGE_HOST}:${BRIDGE_IMAP_PORT} (IMAP STARTTLS) ..."
kubectl delete pod certrefresh --ignore-not-found >/dev/null 2>&1 || true
kubectl run certrefresh --restart=Never --image=alpine/openssl --command -- \
  sh -c "echo Q | openssl s_client -connect ${BRIDGE_HOST}:${BRIDGE_IMAP_PORT} -starttls imap -showcerts 2>/dev/null | openssl x509 -outform pem" \
  >/dev/null

# Wait for the throwaway pod to finish (Succeeded/Failed), then grab its logs.
for _ in $(seq 1 30); do
  phase="$(kubectl get pod certrefresh -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ]; then break; fi
  sleep 1
done
kubectl logs certrefresh > "$CERT_FILE" 2>/dev/null || true

# Validate BEFORE changing anything — never clobber a working pin with garbage.
if ! openssl x509 -in "$CERT_FILE" -noout -subject >/dev/null 2>&1; then
  echo "!! Did not get a valid certificate from ${BRIDGE_HOST}. ConfigMap left unchanged." >&2
  echo "   (Is Bridge running? Try: kubectl get pods -n ${BRIDGE_NS})" >&2
  exit 1
fi
echo ">> Extracted: $(openssl x509 -in "$CERT_FILE" -noout -subject -dates | tr '\n' '  ')"

echo ">> Updating ConfigMap '${NS}/bridge-cert' ..."
kubectl -n "$NS" create configmap bridge-cert \
  --from-file=bridge.crt="$CERT_FILE" \
  --dry-run=client -o yaml | kubectl apply -f -

if kubectl -n "$NS" get deploy/"$DEPLOY" >/dev/null 2>&1; then
  echo ">> Rolling deployment '${NS}/${DEPLOY}' to pick up the new cert ..."
  kubectl -n "$NS" rollout restart deploy/"$DEPLOY"
  kubectl -n "$NS" rollout status deploy/"$DEPLOY" --timeout=120s
  echo ">> Done — Comlink is now pinned to the refreshed Bridge cert."
else
  echo ">> ConfigMap updated. (Deployment '${NS}/${DEPLOY}' not found yet — apply the manifests to deploy.)"
fi
