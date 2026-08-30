# Runtime Config Provenance Tool

**Problem:** Running Kubernetes workloads often drift from their IaC definitions — someone runs `kubectl edit`, patches a ConfigMap, or updates a Secret directly. Existing tools (Terraform, ArgoCD, Flux) only tell you "desired ≠ actual" at the resource level. They don't show you the *effective container config* (merged env vars + mounted ConfigMaps/Secrets + feature flags) and exactly which field changed.

**Why this is different:** Tools like Overmind, Digger, or `terraform plan` show resource-level drift. This tool hashes the *effective runtime config per container* (env vars, mounted ConfigMaps, Secrets, command, args, ports) and compares it against parsed Kubernetes manifests (Deployment/StatefulSet/DaemonSet/Pod YAML). It tells you: "Container `web` env var `FEATURE_NEW_UI` is `true` at runtime but `false` in IaC" — not just "ConfigMap changed."

**Closest alternatives:** `kubectl diff`, ArgoCD diff, `kube-score`, `kube-linter` — all operate on K8s resources, not the merged container runtime view.

---

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  IaC Manifests  │     │  Running Pods    │     │   Comparator        │
│  (YAML files)   │     │  (K8s API)       │     │   (hash + diff)     │
└────────┬────────┘     └────────┬─────────┘     └──────────┬──────────┘
         │                       │                          │
         ▼                       ▼                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ Parse Deploy-   │     │ Extract effective│     │ Match by labels/    │
│ ments, Config-  │     │ config per       │     │ name, compute       │
│ Maps, Secrets   │     │ container:       │     │ per-container hash, │
│ → IaCManifest   │     │ env + mounted    │     │ diff each field     │
└─────────────────┘     │ ConfigMaps/Secrets    │                     │
                        └──────────────────┘     └─────────────────────┘
                                                            │
                                                            ▼
                                                ┌─────────────────────┐
                                                │ DriftReport per pod │
                                                │ - Critical/High/    │
                                                │   Medium/Low        │
                                                │ - Field-level diff  │
                                                └─────────────────────┘
```

1. **Parse IaC**: Reads Kubernetes YAML manifests (Deployment, StatefulSet, DaemonSet, Pod) from local directories. Extracts container spec: image, env, envFrom, command, args, volumes/volumeMounts → ConfigMaps/Secrets.
2. **Capture Runtime**: Queries K8s API for pods in namespace. For each container, resolves *effective* config: merges `env`, `envFrom`, mounted ConfigMap/Secret volumes into a single flat view per container.
3. **Hash & Match**: Computes SHA256 hash per container. Matches runtime pods to IaC manifests by namespace + label (`app=`).
4. **Diff & Report**: Field-by-field comparison. Outputs severity-ranked findings (Critical: image, High: command/args/secrets, Medium: env/ConfigMaps/ports, Low: workingDir).

---

## Quick Start (Demo Mode — Zero Setup)

**Prerequisites:** Python 3.9+

```bash
# Clone and install
git clone <this-repo>
cd runtime-config-provenance
pip install -e .

# Run demo scan (uses built-in sample data, no cluster needed)
config-provenance scan --demo --namespace production
```

### Real Cluster Usage

```bash
# Point at your manifests and cluster
config-provenance scan \
  --namespace production \
  --manifest-dir ./my-manifests \
  --manifest-dir ./base \
  --label-selector app=myapp \
  --output table
```

### Other Commands

```bash
# Validate manifests parse correctly
config-provenance validate --manifest-dir ./manifests

# Hash a specific running pod (requires K8s access)
config-provenance hash production/web-app-7d4b8c9f5-xk2z9

# JSON output for CI/CD
config-provenance scan --demo --output json --fail-on-drift
```

---

## Example Output (Real Run)

### Clean State — No Drift

```bash
$ config-provenance scan --demo --namespace production

 Running in DEMO mode with sample data

 Parsed 2 IaC manifest(s) from sample_manifests/

                               Drift Scan Summary                               
┏━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━┓
┃       ┃       ┃ Runt… ┃ IaC    ┃ Matc… ┃       ┃        ┃      ┃       ┃     ┃
┃ Pod   ┃ Name… ┃ Hash  ┃ Hash   ┃ IaC   ┃ Drift ┃ Criti… ┃ High ┃ Medi… ┃ Low ┃
┡━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━┩
│ web-… │ prod… │ 2222… │ 22226… │ prod… │ NO    │ 0      │ 0    │ 0     │ 0   │
│ api-… │ prod… │ fd3b… │ fd3bc… │ prod… │ NO    │ 0      │ 0    │ 0     │ 0   │
└───────┴───────┴───────┴────────┴───────┴───────┴────────┴──────┴───────┴─────┘

✓ web-app-7d4b8c9f5-xk2z9 - No drift detected
✓ api-service-6f8b9c7d4-mn5p2 - No drift detected
```

### Drift Detected — Simulated Manual Change

Simulate a manual `kubectl edit` changing `FEATURE_NEW_UI` from `true` to `false`:

```bash
$ config-provenance scan --demo --namespace production

 Running in DEMO mode with sample data

 Parsed 2 IaC manifest(s) from sample_manifests/

                               Drift Scan Summary                               
┏━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━┓
┃       ┃       ┃ Runt… ┃ IaC    ┃ Matc… ┃       ┃        ┃      ┃       ┃     ┃
┃ Pod   ┃ Name… ┃ Hash  ┃ Hash   ┃ IaC   ┃ Drift ┃ Criti… ┃ High ┃ Medi… ┃ Low ┃
┡━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━┩
│ web-… │ prod… │ 2e23… │ 22226… │ prod… │ YES   │ 0      │ 0    │ 1     │ 0   │
│ api-… │ prod… │ fd3b… │ fd3bc… │ prod… │ NO    │ 0      │ 0    │ 0     │ 0   │
└───────┴───────┴───────┴────────┴───────┴───────┴────────┴──────┴───────┴─────┘


Drift Details: web-app-7d4b8c9f5-xk2z9
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃           ┃              ┃             ┃           ┃ Runtime      ┃          ┃
┃ Container ┃ Type         ┃ Field       ┃ IaC Value ┃ Value        ┃ Severity ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ web       │ env_vars_mi… │ env_vars.F… │ true      │ false        │ MEDIUM   │
└───────────┴──────────────┴─────────────┴───────────┴──────────────┴──────────┘
✓ api-service-6f8b9c7d4-mn5p2 - No drift detected
```

### JSON Output for CI/CD

```bash
$ config-provenance scan --demo --output json --fail-on-drift
```

```json
{
  "timestamp": "2026-08-29T18:51:08.996158Z",
  "summary": {
    "total_pods": 2,
    "pods_with_drift": 1,
    "total_findings": 1,
    "by_severity": {
      "critical": 0,
      "high": 0,
      "medium": 1,
      "low": 0
    }
  },
  "reports": [
    {
      "pod_name": "web-app-7d4b8c9f5-xk2z9",
      "namespace": "production",
      "runtime_hash": "2e230b7acc994204",
      "iac_hash": "22226d66fdd6e176",
      "matched_iac_source": "/home/abdul/projects/runtime-config-provenance/sample_manifests/production.yaml",
      "has_drift": true,
      "findings": [
        {
          "container_name": "web",
          "drift_type": "env_vars_mismatch",
          "field_path": "env_vars.FEATURE_NEW_UI",
          "iac_value": "true",
          "runtime_value": "false",
          "severity": "medium"
        }
      ]
    },
    {
      "pod_name": "api-service-6f8b9c7d4-mn5p2",
      "namespace": "production",
      "runtime_hash": "fd3bcfa74316c5d3",
      "iac_hash": "fd3bcfa74316c5d3",
      "matched_iac_source": "/home/abdul/projects/runtime-config-provenance/sample_manifests/production.yaml",
      "has_drift": false,
      "findings": []
    }
  ]
}
```

Exit code: `1` (drift detected)

---

## Tech Stack & Libraries Reused

| Library | Purpose | Why |
|---------|---------|-----|
| `kubernetes` (official) | K8s API client | Battle-tested, handles auth/config loading |
| `PyYAML` | YAML parsing | Standard, handles multi-doc YAML |
| `click` | CLI framework | Simple, composable, well-maintained |
| `rich` | Terminal output | Tables, trees, syntax highlighting |
| `hashlib` (stdlib) | SHA256 hashing | No dependency, fast |
| `difflib` (stdlib) | Unified diffs | No dependency, standard format |

**The genuinely new piece:** The *effective container config extraction + per-container hashing + field-level drift classification* pipeline. Existing tools stop at "ConfigMap X changed"; this tool traces it to "Container Y's env var Z = value A at runtime vs value B in IaC."

---

## Known Limitations / What's Next

- **No live Secret decryption in demo** — demo uses plaintext; real cluster mode base64-decodes Secrets automatically
- **Label-based matching only** — matches pods to IaC by `app=` label; could add annotation/ownerReference matching
- **No historical tracking** — stores last N hashes locally (SQLite) to detect drift over time, alert on regressions
- **No Terraform/HCL parsing** — only Kubernetes YAML; could add Terraform JSON plan output support
- **No auto-remediation** — read-only; could add `kubectl rollout restart` suggestion or ArgoCD sync trigger
- **Single-cluster** — no multi-cluster aggregation yet

---

## License

MIT — see [LICENSE](LICENSE)