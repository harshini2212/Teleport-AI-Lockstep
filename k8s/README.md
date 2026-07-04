# k8s — Temporal worker deployment

The lifecycle automation runs as **Temporal workflows in Go** so every
Joiner/Mover/Leaver step is durable, retried, and replayable. These manifests
deploy only the **worker**; the Temporal server is a Helm dependency.

## Apply order

1. **Temporal server (Helm dependency — do this first).** The worker is useless
   without a frontend to connect to:
   ```bash
   helm repo add temporalio https://go.temporal.io/helm-charts
   helm install temporal temporalio/temporal -n temporal --create-namespace
   ```
   This creates the `temporal-frontend` Service on `:7233` that the worker dials.

2. **The worker.**
   ```bash
   kubectl apply -f worker-deployment.yaml
   ```
   The manifest includes the `lifecycle-guard` Namespace, an optional Secret
   stub for `ANTHROPIC_API_KEY`, and the `lifecycle-guard-worker` Deployment
   (built from `go/cmd/worker`).

## Notes

- The worker is **stateless** — all durability lives in the Temporal server's
  datastore — so there is no PVC and it scales horizontally.
- A Temporal worker exposes **no HTTP port**, so health is checked with an
  `exec` probe, not `httpGet`. See the comment block in `worker-deployment.yaml`.
- Provide the Anthropic key (optional, for the NarrateChange activity) via:
  `kubectl -n lifecycle-guard create secret generic lifecycle-guard-secrets --from-literal=anthropic-api-key=sk-ant-...`
