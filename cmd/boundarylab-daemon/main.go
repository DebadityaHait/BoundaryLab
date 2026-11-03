// SPDX-License-Identifier: MIT
// boundarylab-daemon is the BoundaryLab governance daemon binary.
//
// It listens on a Unix domain socket, evaluates incoming CheckRequests from the
// hook binary against the loaded policy set, and writes audit records to SQLite.
//
// Usage:
//
//	boundarylab-daemon [-socket PATH] [-policy-dir DIR] [-audit-db PATH] [-failclosed-log PATH]
//
// The gRPC ext_authz listener address is configured via the BOUNDARYLAB_GRPC_ADDR environment
// variable. The stream/WebSocket server address defaults to :9090 and can be overridden
// with BOUNDARYLAB_DASHBOARD_ADDR.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"boundarylab.local/boundarylab/internal/audit"
	"boundarylab.local/boundarylab/internal/bundle"
	"boundarylab.local/boundarylab/internal/cel"
	"boundarylab.local/boundarylab/internal/daemon"
	"boundarylab.local/boundarylab/internal/delegation"
	grpcauthz "boundarylab.local/boundarylab/internal/grpc"
	"boundarylab.local/boundarylab/internal/ifc"
	"boundarylab.local/boundarylab/internal/label"
	"boundarylab.local/boundarylab/internal/otel"
	"boundarylab.local/boundarylab/internal/policy"
	"boundarylab.local/boundarylab/internal/reload"
	"boundarylab.local/boundarylab/internal/secret"
	"boundarylab.local/boundarylab/internal/stream"
	"boundarylab.local/boundarylab/pkg/boundarylab"

	"boundarylab.local/boundarylab/dashboard"
)

const (
	exitSuccess        = 0 // clean shutdown
	exitStartupFailure = 1 // fatal error during init
	exitRuntimeFailure = 2 // fatal error during operation
	exitConfigError    = 3 // invalid configuration
)

func main() {
	var (
		socketPath    = flag.String("socket", "", "Unix socket path (default: $BOUNDARYLAB_SOCKET_PATH or /tmp/boundarylab.sock)")
		policyDir     = flag.String("policy-dir", "policies", "Policy YAML directory (recursively loads all subdirectories)")
		auditDB       = flag.String("audit-db", "~/.boundarylab/audit.db", "Audit SQLite database path")
		failClosedLog = flag.String("failclosed-log", "", "Fail-closed log path (default: $BOUNDARYLAB_FAILCLOSED_LOG or ~/.boundarylab/failclosed.log)")
	)
	flag.Parse()

	pidLock, err := daemon.AcquirePIDLock(filepath.Join(expandHome("~/.boundarylab"), "daemon.pid"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: %v\n", err)
		os.Exit(exitStartupFailure)
	}
	defer func() { _ = pidLock.Unlock() }()

	cfg := daemon.Config{
		SocketPath:    *socketPath,
		PolicyDir:     *policyDir,
		AuditDBPath:   expandHome(*auditDB),
		FailClosedLog: *failClosedLog,
	}

	otelCfg := otel.Config{
		Enabled:     os.Getenv("BOUNDARYLAB_OTEL_ENDPOINT") != "",
		Endpoint:    os.Getenv("BOUNDARYLAB_OTEL_ENDPOINT"),
		ServiceName: "boundarylab-daemon",
	}
	otelShutdown, err := otel.Initialize(otelCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: OTel init failed: %v\n", err)
		os.Exit(exitStartupFailure)
	}
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		if shutErr := otelShutdown(shutCtx); shutErr != nil {
			fmt.Fprintf(os.Stderr, "boundarylab-daemon: OTel shutdown error: %v\n", shutErr)
		}
	}()
	if otelCfg.Enabled {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: OTel enabled → %s\n", otelCfg.Endpoint)
	}

	auditWriter, err := audit.NewWriter(cfg.AuditDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to open audit database %q: %v\n", cfg.AuditDBPath, err)
		os.Exit(exitStartupFailure)
	}

	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to create CEL environment: %v\n", err)
		os.Exit(exitStartupFailure)
	}

	// Create a delegation engine with an ephemeral key so the HTTP API is
	// available from startup. Chains are registered by the policy engine at
	// runtime. Only tokens verified by this key can be accepted by the evaluator.
	delegPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to generate ephemeral delegation key: %v\n", err)
		os.Exit(exitStartupFailure)
	}
	delegEngine, err := delegation.New(delegPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to create delegation engine: %v\n", err)
		os.Exit(exitStartupFailure)
	}

	engine := policy.NewPolicyEngine(
		sessions,
		celEnv,
		policy.WithSecretScanner(secret.NewScanner()),
		policy.WithDelegationValidator(delegEngine),
		policy.WithLabeler(label.NewLabeler()),
	)

	ctx, cancel := context.WithCancel(context.Background())

	// initialPolicyCount is set to len(templates) on a successful startup load.
	// It is used after the stream server starts to emit bundle.activated.
	var initialPolicyCount int
	templates, bindings, err := bundle.ParsePolicyDir(cfg.PolicyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to parse policies from %q: %v\n", cfg.PolicyDir, err)
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: starting with no policies (all requests will be denied)\n")
	} else {
		compiled := &boundarylab.CompiledBundle{
			Version:   1,
			Templates: templates,
			Bindings:  bindings,
		}
		if err := engine.Reload(ctx, compiled); err != nil {
			fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to load initial policies: %v\n", err)
		} else {
			initialPolicyCount = len(templates)
			fmt.Fprintf(os.Stderr, "boundarylab-daemon: loaded %d policies from %s\n", initialPolicyCount, cfg.PolicyDir)
		}
	}
	if grpcAddr := os.Getenv("BOUNDARYLAB_GRPC_ADDR"); grpcAddr != "" {
		grpcSrv, err := grpcauthz.NewServer(grpcauthz.Config{
			ListenAddr: grpcAddr,
			Engine:     engine,
			Timeout:    50 * time.Millisecond,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to create gRPC server: %v\n", err)
			os.Exit(exitStartupFailure)
		}
		go func() {
			if err := grpcSrv.Start(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "boundarylab-daemon: gRPC server error: %v\n", err)
			}
		}()
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: gRPC ext_authz listening on %s\n", grpcAddr)
	}

	// Start reload watcher after initial policy load (spec: started AFTER initial compile).
	pr := &policyReloader{
		policyDir: cfg.PolicyDir,
		engine:    engine,
		ctx:       ctx,
	}
	reloadWatcher, rwErr := reload.NewReloadWatcher(cfg.PolicyDir, pr)
	if rwErr != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: failed to create reload watcher: %v\n", rwErr)
	} else {
		go func() {
			if err := reloadWatcher.Start(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "boundarylab-daemon: reload watcher error: %v\n", err)
			}
		}()
	}

	streamSrv := stream.NewStreamServer(nil, nil,
		stream.WithEvaluator(engine),
		stream.WithPolicyLister(engine),
		stream.WithStaticFS(dashboard.FS),
		stream.WithRouteRegistrar(func(mux *http.ServeMux) {
			daemon.RegisterCheckHandler(mux, engine)
		}),
	)
	streamCtx, streamCancel := context.WithCancel(ctx)
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		addr := os.Getenv("BOUNDARYLAB_DASHBOARD_ADDR")
		if addr == "" {
			addr = "127.0.0.1:9090"
		}
		// Extract port for log messages; fall back to the raw addr if malformed.
		port := addr
		if _, p, err := net.SplitHostPort(addr); err == nil {
			port = p
		}
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: dashboard at http://localhost:%s\n", port)
		fmt.Fprintf(os.Stderr, "boundarylab-daemon:   (remote access: set window.__BOUNDARYLAB_DAEMON_URL__ in browser console)\n")
		if err := streamSrv.Start(streamCtx, addr); err != nil && streamCtx.Err() == nil {
			if isAddrInUse(err) {
				fmt.Fprintf(os.Stderr, "FATAL: Cannot bind %s — port already in use.\n  Check: lsof -i :%s\n  Fix: set BOUNDARYLAB_DASHBOARD_ADDR=127.0.0.1:<other-port>\n", addr, port)
			} else {
				fmt.Fprintf(os.Stderr, "boundarylab-daemon: stream server error: %v\n", err)
			}
		}
	}()
	// Wire audit checkpoint → stream event so the dashboard Forensic Review shows live data.
	auditWriter.SetCheckpointEmitFn(func(seq int64, hash, prevHash string, eventCount int) {
		streamSrv.EmitAuditCheckpoint(ctx, seq, hash, prevHash, eventCount)
	})

	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)
		auditWriter.Start(ctx)
	}()

	// Graceful shutdown: cancel the stream server context and wait for it to
	// drain connections and release the TCP port before the process exits.
	// Without this wait the goroutine never gets scheduled and the port lingers
	// in TIME_WAIT, causing "address already in use" on rapid restart.
	defer func() {
		streamCancel()
		select {
		case <-streamDone:
		case <-time.After(6 * time.Second): // stream server has 5s shutdown timeout
			fmt.Fprintf(os.Stderr, "boundarylab-daemon: stream server drain timed out\n")
		}
	}()

	// Emit bundle.activated so the dashboard shows the policies loaded at startup.
	// The payload is stored in the stream server and replayed to each client on connect,
	// so this call is safe to make before any clients have connected.
	if initialPolicyCount > 0 {
		streamSrv.EmitBundleActivated(ctx, 1, "", initialPolicyCount, false)
	}

	delegEngine.SetEmitFn(func(eventType, chainID, reason string) {
		streamSrv.Emit(ctx, boundarylab.StreamEvent{
			Type:      eventType,
			SessionID: chainID,
			Reason:    reason,
			Timestamp: time.Now().UnixNano(),
		})
	})

	d := daemon.New(cfg, engine, auditWriter, streamSrv, sessions)
	d.SetDelegationEngine(delegEngine)
	d.SetReloader(pr)
	d.SetAuditContext(cancel, auditDone)

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "boundarylab-daemon: %v\n", err)
		os.Exit(exitRuntimeFailure)
	}
}

// policyReloader adapts PolicyEngine.Reload to the reload.PolicyReloader interface.
// It re-parses the policy directory and calls engine.Reload on each file-change event.
type policyReloader struct {
	policyDir string
	engine    *policy.PolicyEngine
	ctx       context.Context
}

func (r *policyReloader) Invalidate() { r.engine.Invalidate() }

func (r *policyReloader) Reload() error {
	templates, bindings, err := bundle.ParsePolicyDir(r.policyDir)
	if err != nil {
		r.engine.Invalidate()
		return err
	}
	compiled := &boundarylab.CompiledBundle{
		Version:   1,
		Templates: templates,
		Bindings:  bindings,
	}
	return r.engine.Reload(r.ctx, compiled)
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return home + path[1:]
}

// isAddrInUse reports whether the error is caused by EADDRINUSE.
func isAddrInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return errors.Is(sysErr.Err, syscall.EADDRINUSE)
		}
	}
	return false
}
