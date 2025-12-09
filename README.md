# eBPF-Based Cloud Runtime Security Monitor (Educational)

Synthetic, read-only runtime visibility stack combining kernel eBPF, Go agent rules, a dashboard, and Kubernetes deployment assets. Built to be safe, synthetic, and instructional.

## How it works (eBPF overview)
- eBPF hooks attach to safe syscall tracepoints (`execve`, `connect`, `ptrace`, `memfd_create`, `mmap`).
- Programs collect lightweight metadata (PID/PPID, comm, filename, dst IP/port, cgroup ID) and emit it via perf buffer.
- No kernel modules, no data tampering—read-only introspection only.

## Architecture
```
+----------------+      +----------------------+      +------------------+
| eBPF programs  | -->  | Go agent & rules     | -->  | Dashboard (React)|
| exec/connect   |      | perf reader + enrich |      | WebSocket feed   |
| ptrace/mmap    |      | container/K8s meta   |      | live visuals     |
+----------------+      +----------------------+      +------------------+
         ^                          |                         |
         |                          v                         |
         |                  Synthetic sims                   |
         |          (reverse shell / injection)              |
         +---------------------------------------------------+
```

Additional design notes live in `docs/ARCHITECTURE.md` (includes Mermaid flow).

## Repository layout
- `ebpf/process_monitor.c` — tracepoint programs emitting perf events.
- `agent/` — Go user space loader, enrichment, and rules engine.
- `dashboard/` — React UI (Vite) for live alerts/heatmap.
- `deploy/helm/` — Helm chart (DaemonSet for agent, dashboard Deployment, RBAC, ConfigMap).
- `scripts/` — Safe simulations (`simulate_reverse_shell.sh`, `simulate_injection.py`).
- `tests/` — Go unit tests for rule logic.
- `docs/` — Architecture/design documentation.
- `docs/API.md` — SSE endpoint and alert schema reference.

## Detection rules (summary)
- **Reverse Shell**: outbound TCP to {4444, 8081, 9001} _or_ binary in {bash, sh, zsh, python} while user != root.
- **Process Injection**: ptrace attach, `mmap` with `PROT_EXEC`, or `memfd_create` triggers `injection_attempt` alert.
- **Suspicious Exec**: binaries from `/tmp`, anonymous memfd, or orphaned non-root children (PPID=1).

### Example alert (JSON)
```json
{
  "rule_id": "reverse_shell",
  "severity": "high",
  "risk_score": 85,
  "reason": "reverse shell signature: known C2 port",
  "event": {
    "PID": 1234,
    "PPID": 567,
    "UID": 1000,
    "DstPort": 15104,
    "Comm": "bash",
    "EventType": "connect"
  },
  "container": {"id": "abcd1234", "runtime": "cgroup"},
  "timestamp": "2025-01-01T00:00:00Z",
  "addr": "10.0.0.5:4444"
}
```

## Build & run locally (educational)
1. Compile eBPF (requires clang/LLVM and kernel headers):
   ```bash
   cd ebpf
   clang -O2 -g -target bpf -c process_monitor.c -o process_monitor.bpf.o
   ```
2. Run the Go agent (needs root/BPF permissions):
   ```bash
   cd agent
   go run ./
   ```
   It loads `../ebpf/process_monitor.bpf.o`, reads perf events, enriches with cgroup/K8s hints, and prints JSON alerts.
3. Dashboard (optional demo, consumes SSE at `/events`):
   ```bash
   cd dashboard
   npm install
   npm run dev -- --host
   ```
   Set `VITE_EVENTS_URL` if the SSE endpoint is different (default `http://localhost:8090/events`).

## Kubernetes (Helm) quickstart
```
helm install runtime ./deploy/helm \
  --set image.agent="ghcr.io/you/runtime-agent:tag" \
  --set image.dashboard="ghcr.io/you/runtime-dashboard:tag"
```
- DaemonSet runs the agent with BPF privileges (hostPID + BPF/SYS_ADMIN caps).
- Dashboard served via ClusterIP service on port 8080.
- ConfigMap `runtime-security-monitor-rules` carries the educational rule set.

## Synthetic attack simulations
- Reverse shell: `bash scripts/simulate_reverse_shell.sh` (local-only nc, safe to stop via trap).
- Injection: `python3 scripts/simulate_injection.py` (self-ptrace attach/detach for a single event).

## Why kernel-level visibility?
- Syscall-layer telemetry sees short-lived or fileless activity before user space logs exist.
- eBPF provides low-overhead, programmable filters without kernel modules.
- Container/cgroup IDs allow per-pod attribution even with shared nodes.

## Testing
- Run Go unit tests for rules:
  ```bash
  go test ./tests
  ```
- Lint/format:
  - Go: `gofmt -w agent/*.go`
  - JS/React: `npm run build` (ensures Vite build passes)

## Governance & security
- Contribution guidelines: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security policy: `SECURITY.md`
- License: MIT (`LICENSE`)

## Dashboard snapshot (concept)
- Live alerts stream (rule, PID, container, reason)
- Pod heatmap indicating alert density
- Process lineage (PPID → PID)
- Reverse shell and injection highlight panels
- CPU/network mini-bars for quick anomaly hints

## Safety notes
- Only safe tracepoints; no writes to kernel memory.
- Metadata only (no payloads, no secrets).
- Simulations are local and self-contained; adapt targets as needed in isolated labs.
