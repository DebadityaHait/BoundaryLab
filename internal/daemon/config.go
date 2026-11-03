// SPDX-License-Identifier: MIT
// Package daemon implements the BoundaryLab governance daemon: Unix socket listener,
// length-prefixed JSON framing, policy evaluation dispatch, and graceful shutdown.
//
// Critical invariants enforced here:
//   - No atomic.Pointer.Store() in this package — PolicyEngine owns reload.
//   - Every error path returns Decision{Action: ActionDeny} (fail-secure, A5).
//   - MaxMessageSize (2MB) enforced at framing layer before any allocation.
//   - Per-connection 5s I/O deadline (latency budget tracked via OTel).
//   - Graceful shutdown: drain in-flight → close listener → flush audit.
package daemon

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// maxConcurrentConnections bounds the accept loop semaphore.
	maxConcurrentConnections = 128
	socketPermissions        = 0600
	socketDirPermissions     = 0700
	// evaluationDeadline is the per-connection I/O timeout. This must be long
	// enough for CEL evaluation + JSON marshaling under worst-case load with
	// -race instrumentation. The 50ms latency *budget* is tracked via OTel, not
	// enforced by killing connections.
	evaluationDeadline = 5 * time.Second
)

// Config carries daemon startup parameters.
type Config struct {
	SocketPath  string
	PolicyDir   string
	AuditDBPath string
	// FailClosedLog defaults to ~/.boundarylab/failclosed.log (or $BOUNDARYLAB_FAILCLOSED_LOG).
	FailClosedLog string
	// HealthzAddr is the address for the /healthz HTTP endpoint. Defaults to "127.0.0.1:9091".
	HealthzAddr string
}

// defaultSocketPath returns the canonical Unix socket path.
// Priority: $BOUNDARYLAB_SOCKET_PATH → $XDG_RUNTIME_DIR/boundarylab/boundarylab.sock → /tmp/boundarylab.sock
func defaultSocketPath() string {
	if v := os.Getenv("BOUNDARYLAB_SOCKET_PATH"); v != "" {
		return v
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return filepath.Join(xdg, "boundarylab", "boundarylab.sock")
	}
	return "/tmp/boundarylab.sock"
}

// defaultFailClosedLog returns the default fail-closed log path.
func defaultFailClosedLog() string {
	if v := os.Getenv("BOUNDARYLAB_FAILCLOSED_LOG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/boundarylab-failclosed.log"
	}
	return filepath.Join(home, ".boundarylab", "failclosed.log")
}

// applyDefaults fills in zero-value Config fields.
func (c *Config) applyDefaults() {
	if c.SocketPath == "" {
		c.SocketPath = defaultSocketPath()
	}
	if c.FailClosedLog == "" {
		c.FailClosedLog = defaultFailClosedLog()
	}
	if c.HealthzAddr == "" {
		c.HealthzAddr = "127.0.0.1:9091"
	}
}
