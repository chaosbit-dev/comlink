# Comlink on Gonk — durable K3s deploy runbook

Read-only Comlink, containerized, running as a standalone Deployment in the
`comlink` namespace. It connects to Proton Bridge at the in-cluster Service and
is fronted by the existing cloudflared tunnel + Cloudflare Access. This replaces
the throwaway `uv run comlink` on the host + manual `kubectl port-forward` to
Bridge.

All commands run **on Gonk** unless noted. Run them in order.

---

## 0. Prerequisites

- `~/comlink/bridge.crt` exists and is a clean PEM (the pinned Bridge cert).
  Sanity check: `openssl x509 -in ~/comlink/bridge.crt -noout -subject` should
  print a subject (localhost / 127.0.0.1), not an error.
- The Bridge app password is in Vaultwarden (Bitwarden `bw` CLI logged in/unlocked).
- The Deployment expects the proton-bridge Service at
  `proton-bridge.proton-bridge.svc.cluster.local:1143` (STARTTLS). Confirm it
  resolves in-cluster before cutover (step 7).
- Repo checked out on Gonk with this `Dockerfile` + `deploy/` present.

---

## 1. Build the image on Gonk and import into k3s containerd

No external registry. Build locally, then import into the k3s containerd
namespace (`k8s.io`) so the kubelet finds it with `imagePullPolicy: IfNotPresent`.
**The tag must be exactly `comlink:0.1.0`** to match `deployment.yaml`.

### Variant A — docker build + `k3s ctr images import` (matches the existing host)

```bash
cd ~/path/to/comlink            # repo root (where the Dockerfile is)

docker build -t comlink:0.1.0 .

# Stream the image straight into k3s's containerd (namespace k8s.io).
docker save comlink:0.1.0 | sudo k3s ctr --namespace k8s.io images import -

# Verify it landed:
sudo k3s ctr --namespace k8s.io images ls | grep comlink:0.1.0
```

### Variant B — nerdctl (build directly in the k8s.io containerd namespace)

If you use nerdctl/containerd without docker, build straight into the namespace
the kubelet reads — no save/import round-trip:

```bash
cd ~/path/to/comlink

sudo nerdctl --namespace k8s.io build -t comlink:0.1.0 .

# Verify:
sudo nerdctl --namespace k8s.io images | grep comlink
```

> Tag/pullPolicy contract: `deployment.yaml` pins `image: comlink:0.1.0` with
> `imagePullPolicy: IfNotPresent`. Since there's no registry, the tag must
> already exist in the `k8s.io` containerd namespace from the step above. If you
> ever rebuild the same `:0.1.0` tag with new code, `IfNotPresent` will keep the
> OLD cached image — bump the tag (`:0.1.1`) and update `deployment.yaml`, or the
> pod won't pick up changes. (Use `Never` instead of `IfNotPresent` if you want
> the deploy to fail loudly rather than ever reach for a registry.)

---

## 2. Create the namespace

```bash
kubectl apply -f deploy/00-namespace.yaml
```

(The file is named `00-namespace.yaml` so that `kubectl apply -f deploy/`
applies it first — alphabetical order, before the namespaced resources.)

---

## 3. Create the Bridge-password Secret (from Vaultwarden)

A template lives at `deploy/examples/secret.example.yaml` (placeholder only, and
deliberately kept out of the apply path — see step 5). Create the real Secret
imperatively so the plaintext never lands in a file:

```bash
# Pull the Bridge app password out of Vaultwarden into a shell var, create the
# Secret, then scrub the var. Adjust the item name to match your vault.
PW="$(bw get password 'Proton Bridge app password')"
kubectl -n comlink create secret generic comlink-bridge \
    --from-literal=password="$PW"
unset PW
```

Verify the key exists (value stays hidden):

```bash
kubectl -n comlink get secret comlink-bridge -o jsonpath='{.data.password}' | base64 -d | wc -c
# -> a non-zero byte count = present. (Don't print the value itself.)
```

> This is the **Bridge app password**, not the Proton account password. It
> surfaces in the pod as `COMLINK_PASSWORD`. Comlink redacts it from logs and
> error strings, but treat the Secret as sensitive regardless.

---

## 4. Create the Bridge-cert ConfigMap

```bash
cd ~/comlink                    # where bridge.crt lives
kubectl -n comlink create configmap bridge-cert --from-file=bridge.crt=./bridge.crt
```

This mounts read-only at `/etc/comlink/bridge.crt`, which is exactly
`COMLINK_TLS_CERT_PATH` in the Deployment. `verify-no-hostname` requires this
cert to be present, or the pod refuses to start (config validation in
`config.py`).

> **Refreshing the cert later.** Bridge regenerates this self-signed cert if you
> ever re-auth or reinstall it — the pin will then mismatch and IMAP TLS fails.
> When that happens, run **`bash deploy/refresh-bridge-cert.sh`**: it re-extracts
> the cert Bridge currently presents, validates it, updates this ConfigMap, and
> rolls the Deployment to pick it up — one command, and it won't clobber a working
> pin with a bad extraction. (It also works here for the initial create.)

---

## 5. Apply the workload

The Secret and ConfigMap were already created imperatively (steps 3–4). The
example Secret now lives under `deploy/examples/`, and `kubectl apply -f deploy/`
is **non-recursive** — it applies only the top-level `00-namespace.yaml`,
`deployment.yaml`, and `service.yaml` in alphabetical order (namespace first, so
no ordering error; the `.sh`/`.md` and `examples/` are ignored). So this is safe
and won't touch your real Secret:

```bash
kubectl apply -f deploy/
```

Watch it come up:

```bash
kubectl -n comlink rollout status deploy/comlink --timeout=120s
kubectl -n comlink get pods -l app.kubernetes.io/name=comlink
kubectl -n comlink logs deploy/comlink
```

Expect a startup log line for the streamable-http transport on `0.0.0.0:8000/mcp`
and a "DNS-rebinding protection ON; allowed_hosts=['mcp-comlink.chaosbit.dev']"
line. If you instead see the config error about `verify-no-hostname` requiring a
cert, the ConfigMap (step 4) is missing or mis-mounted.

---

## 6. Verify in-cluster (before touching the tunnel)

Port-forward the **Comlink Service** (not Bridge anymore) and hit the MCP
endpoint with the correct Host header (DNS-rebinding protection is on):

```bash
kubectl -n comlink port-forward svc/comlink 8000:8000 &
PF_PID=$!

# MCP streamable-http expects a POST; a bare GET is enough to prove the listener
# answers and the Host allowlist works. With the right Host header you should NOT
# get a 421/400 host-rejection:
curl -i -H 'Host: mcp-comlink.chaosbit.dev' http://127.0.0.1:8000/mcp

# Negative check — wrong Host should be rejected by transport security:
curl -i -H 'Host: evil.example' http://127.0.0.1:8000/mcp

kill "$PF_PID"
```

There is no plain HTTP health route by design; the probes are TCP-only. "The
port answers and the right Host is accepted" is the bar here. Bridge
reachability is exercised by the `proton_health_check` MCP tool once a client is
connected, not by an HTTP probe.

---

## 7. Repoint the cloudflared tunnel to the Service

Update the cloudflared ingress for `mcp-comlink.chaosbit.dev` from the bare
host (`http://localhost:8000` / `host:8000`) to the in-cluster Service.

If cloudflared runs **outside** the cluster on the Gonk host, the Service isn't
directly reachable by ClusterIP — point it at the kube DNS name only if
cloudflared runs in-cluster. Two cases:

- **cloudflared runs in-cluster (a pod):** set the ingress service to
  `http://comlink.comlink.svc.cluster.local:8000`.
- **cloudflared runs on the host (systemd/binary):** keep a localhost target but
  move it onto the Service via a stable port-forward / nodePort, OR move
  cloudflared into the cluster. Simplest interim: a host-level
  `kubectl -n comlink port-forward --address 127.0.0.1 svc/comlink 8000:8000`
  unit and leave the ingress at `http://localhost:8000`. (This trades one
  port-forward for another but now targets the durable pod, not the bare
  process.)

**Critical:** the tunnel MUST preserve the original Host header
`mcp-comlink.chaosbit.dev`. Comlink's `COMLINK_HTTP_ALLOWED_HOSTS` rejects any
other Host. In a cloudflared `config.yaml` ingress, do **not** set
`httpHostHeader` to anything else, and do not override it to the origin's
hostname. If the phone starts getting host-rejection errors after cutover, this
is the cause.

Example cloudflared ingress snippet (in-cluster service target):

```yaml
ingress:
  - hostname: mcp-comlink.chaosbit.dev
    service: http://comlink.comlink.svc.cluster.local:8000
    # Do NOT add httpHostHeader here — let the original Host pass through.
  - service: http_status:404
```

Restart/reload cloudflared after editing.

---

## 8. Confirm the phone still reads

From the Claude mobile app (the connector behind Cloudflare Access), exercise a
read tool — e.g. `proton_health_check` or `proton_list_folders`. A healthy
result confirms: CF Access -> tunnel -> Service -> pod -> Bridge all the way
through. `proton_health_check` will also report Bridge IMAP reachability and the
read-only send-gate status.

---

## 9. Cutover (decommission the throwaway path)

Only after step 8 passes:

```bash
# Stop the bare host process (however it's run — systemd unit, tmux, nohup):
#   systemctl --user stop comlink   # if a unit
#   or: pkill -f 'uv run comlink'
#   or: kill the tmux/nohup PID

# Kill the old manual Bridge port-forward used by the bare process:
#   pkill -f 'port-forward.*1143'   # the old Bridge forward, NOT the step-6 one
```

The durable pod now owns the path. Confirm nothing still listens on the host's
8000 except the intended cloudflared/port-forward target.

---

## 10. Rollback

If the pod path regresses:

```bash
# 1. Revert the cloudflared ingress for mcp-comlink.chaosbit.dev back to the
#    bare host target (http://localhost:8000) and reload cloudflared.
# 2. Restart the bare process on the host:
#       cd ~/path/to/comlink
#       COMLINK_TRANSPORT=streamable-http COMLINK_HTTP_HOST=0.0.0.0 \
#       COMLINK_HTTP_ALLOWED_HOSTS=mcp-comlink.chaosbit.dev \
#       ...(other COMLINK_* env as before)... uv run comlink
# 3. Re-establish the manual Bridge port-forward the bare process needs.
# 4. Optionally scale the pod down so it isn't competing:
#       kubectl -n comlink scale deploy/comlink --replicas=0
```

The pod, Secret, ConfigMap, and image remain in place for a retry — fix forward,
bump the image tag if code changed, and re-cut.

---

## Teardown (full removal)

```bash
kubectl delete -f deploy/deployment.yaml -f deploy/service.yaml
kubectl -n comlink delete configmap bridge-cert
kubectl -n comlink delete secret comlink-bridge
kubectl delete -f deploy/00-namespace.yaml
sudo k3s ctr --namespace k8s.io images rm comlink:0.1.0   # or nerdctl rmi
```
