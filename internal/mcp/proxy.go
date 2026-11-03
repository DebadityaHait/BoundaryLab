// SPDX-License-Identifier: MIT
package mcp

import (
	"context"
	"encoding/json"
	"log"
	"sync"

	"boundarylab.local/boundarylab/internal/policy"
	"boundarylab.local/boundarylab/pkg/boundarylab"
)

// GovernancePipeline evaluates a tool call through BoundaryLab policy.
type GovernancePipeline interface {
	Evaluate(ctx context.Context, req boundarylab.CheckRequest) boundarylab.CheckResponse
}

// MCPProxy is the bidirectional MCP proxy with governance.
type MCPProxy struct {
	upstream  Upstream
	pipeline  GovernancePipeline
	tracker   *IntegrityTracker
	scanner   policy.SecretScanner
	sessionID string
	wg        sync.WaitGroup
}

// New returns an MCPProxy using the provided tracker for drift detection.
// Use NewIntegrityTrackerWithDB for persistence across daemon restarts.
func New(
	upstream Upstream,
	pipeline GovernancePipeline,
	scanner policy.SecretScanner,
	sessionID string,
	tracker *IntegrityTracker,
) *MCPProxy {
	return &MCPProxy{
		upstream:  upstream,
		pipeline:  pipeline,
		tracker:   tracker,
		scanner:   scanner,
		sessionID: sessionID,
	}
}

// NewInMemory creates an MCPProxy with in-memory drift tracking (no persistence across restarts).
// Use New() with NewIntegrityTrackerWithDB() for production.
func NewInMemory(
	upstream Upstream,
	pipeline GovernancePipeline,
	scanner policy.SecretScanner,
	sessionID string,
) *MCPProxy {
	return New(upstream, pipeline, scanner, sessionID, NewIntegrityTracker())
}

// HandleRequest dispatches a JSON-RPC request through the governance pipeline.
func (p *MCPProxy) HandleRequest(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "tools/call":
		return p.handleToolCall(ctx, req)
	case "tools/list":
		return p.handleToolsList(ctx, req)
	case "initialize", "ping", "notifications/initialized":
		result, err := p.upstream.Call(ctx, req.Method, req.Params)
		if err != nil {
			return errorResponse(req.ID, -32603, err.Error())
		}
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	default:
		return errorResponse(req.ID, -32601, "method is not governed by BoundaryLab")
	}
}

// Wait blocks until all background goroutines launched by HandleRequest finish.
func (p *MCPProxy) Wait() {
	p.wg.Wait()
}

// handleToolCall runs the governance pipeline and conditionally forwards.
func (p *MCPProxy) handleToolCall(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	toolName, argsJSON, err := extractToolCall(req.Params)
	if err != nil {
		return errorResponse(req.ID, -32600, "invalid tools/call params")
	}

	// Drift check: fail-secure before any policy evaluation.
	if p.tracker.IsDrifted(toolName) {
		return errorResponse(req.ID, -32603, "tool definition has drifted — approval required")
	}

	checkReq := boundarylab.CheckRequest{
		Tool:      toolName,
		Args:      argsJSON,
		SessionID: p.sessionID,
	}

	resp := p.pipeline.Evaluate(ctx, checkReq)

	switch resp.Decision.Action {
	case boundarylab.ActionAllow, boundarylab.ActionAudit:
		if p.scanner == nil {
			return errorResponse(req.ID, -32603, "response scanner is unavailable")
		}
		result, callErr := p.upstream.Call(ctx, req.Method, req.Params)
		if callErr != nil {
			return errorResponse(req.ID, -32603, callErr.Error())
		}
		if len(result) > 1<<20 {
			return errorResponse(req.ID, -32603, "tool response exceeds secret scanning limit")
		}
		findings, scanLabel := p.scanner.ScanBoundary(ctx, string(result), policy.BoundaryToolResponse)
		if len(findings) > 0 || scanLabel != (boundarylab.SecurityLabel{}) {
			return errorResponse(req.ID, -32603, "tool response blocked by secret scan")
		}

		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}

	case boundarylab.ActionRequireApproval:
		return errorResponse(req.ID, -32603, "approval required: "+resp.Decision.Reason)

	case boundarylab.ActionDeny:
		reason := resp.Decision.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		return errorResponse(req.ID, -32603, reason)
	}

	// Zero value and any unrecognised action: fail-secure deny (INV-001).
	reason := resp.Decision.Reason
	if reason == "" {
		reason = "denied by policy"
	}
	return errorResponse(req.ID, -32603, reason)
}

// handleToolsList intercepts tools/list, checks drift, then returns the result.
func (p *MCPProxy) handleToolsList(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	tools, err := p.upstream.ListTools(ctx)
	if err != nil {
		return errorResponse(req.ID, -32603, err.Error())
	}

	for _, tool := range tools {
		hasDrift, baselineHash := p.tracker.CheckDrift(tool)
		if hasDrift {
			currentHash := p.tracker.Fingerprint(tool)
			log.Printf("mcp.tool_drift: tool=%s baseline=%x current=%x", tool.Name, baselineHash, currentHash)
		}
	}

	// Re-encode the tools list as the response result.
	result, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		return errorResponse(req.ID, -32603, "marshal tools: "+err.Error())
	}
	return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// extractToolCall pulls tool name and args from tools/call params JSON.
func extractToolCall(params json.RawMessage) (string, json.RawMessage, error) {
	if len(params) == 0 {
		return "", nil, errorf("empty params")
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "", nil, err
	}
	if p.Name == "" {
		return "", nil, errorf("missing name")
	}
	return p.Name, p.Arguments, nil
}

// errorResponse constructs a JSON-RPC error response.
func errorResponse(id json.RawMessage, code int, message string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: message},
	}
}

// errorf returns a simple error from a string (avoids fmt import in hot path).
type proxyError string

func errorf(s string) proxyError { return proxyError(s) }

func (e proxyError) Error() string { return string(e) }
