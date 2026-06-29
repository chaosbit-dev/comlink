# cloudflared in-cluster — migrate the Gonk tunnel off the host

Moves the `gonk` tunnel (`dfb3fb6c-3782-467e-be46-057a91937bd9`) from the host
systemd `cloudflared` into a K3s Deployment. Targets are converted from
hardcoded ClusterIPs to stable Service DNS names. Zero-downtime: the same tunnel
runs from both host and cluster during the overlap (Cloudflare load-balances
connections across cloudflared replicas), then you stop the host one.

> **Shared infra note:** this tunnel fronts `remote`, `mcp-ha`, *and*
> `mcp-comlink` — it's not comlink-specific. It lives here for convenience; move
> it to a dedicated infra repo if you prefer.

## Prerequisites

- The comlink pod is already deployed (`comlink.comlink.svc.cluster.local:8000`
  resolves) — so the in-cluster config's comlink target is live before cutover.
- You have the host tunnel credentials at
  `/etc/cloudflared/dfb3fb6c-3782-467e-be46-057a91937bd9.json`.
- Pin `deployment.yaml`'s image off `:latest` to a current
  [cloudflared release](https://github.com/cloudflare/cloudflared/releases).

## Steps (on Gonk)

```bash
# 1. Namespace
kubectl apply -f deploy/cloudflared/namespace.yaml

# 2. Tunnel credentials -> Secret (from the host creds file; never commit this)
sudo kubectl -n cloudflared create secret generic cloudflared-creds \
  --from-file=credentials.json=/etc/cloudflared/dfb3fb6c-3782-467e-be46-057a91937bd9.json
# (sudo only if the file is root-readable; otherwise drop it)

# 3. Config + Deployment
kubectl apply -f deploy/cloudflared/configmap.yaml -f deploy/cloudflared/deployment.yaml

# 4. Confirm the in-cluster replicas registered with the tunnel
kubectl -n cloudflared rollout status deploy/cloudflared --timeout=120s
kubectl -n cloudflared logs deploy/cloudflared | grep -iE "registered|connection|ready"
cloudflared tunnel info gonk        # should now show MORE connections (host + cluster)
```

At this point the tunnel is served from **both** host and cluster. `remote` and
`mcp-ha` are identical in both configs, so they're consistent. `mcp-comlink`
differs (host → bare `:8000`, cluster → the pod), so during this overlap those
requests split between the two — harmless if both serve, but keep the overlap
short.

```bash
# 5. Cutover: stop + disable the HOST cloudflared. In-cluster now owns the tunnel.
sudo systemctl disable --now cloudflared

# 6. Verify all three hostnames through the (now in-cluster only) tunnel
for h in remote.chaosbit.dev mcp-ha.chaosbit.dev; do
  echo "== $h =="; curl -sS -o /dev/null -w "%{http_code}\n" "https://$h/"
done
# mcp-comlink is gated by Cloudflare Access — confirm via the Claude mobile app
# ("what's unread in my inbox?") rather than curl.

# 7. Decommission the bare comlink process (no longer referenced by any ingress)
#    pkill -f 'uv run comlink'   ;  and kill the old `kubectl port-forward ... 1143`
```

## Rollback

```bash
# Re-enable the host tunnel and stand down the in-cluster one:
sudo systemctl enable --now cloudflared
kubectl -n cloudflared scale deploy/cloudflared --replicas=0
```
The host `config.yml` is unchanged, so re-enabling restores the prior state
exactly (including `mcp-comlink` → bare `:8000`, so restart that process too if
you've already decommissioned it).

## If you ever change ingress

Edit `configmap.yaml`, `kubectl apply` it, then
`kubectl -n cloudflared rollout restart deploy/cloudflared` so the pods reload.
