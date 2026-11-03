// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"boundarylab.local/boundarylab/pkg/boundarylab"
)

// GenericAdapter is the fallback adapter for unknown IDEs.
// It accepts any JSON with "tool_name" or "tool" field and uses best-effort parsing.
// Output uses the Claude Code format. Denials and approval requests exit nonzero.
type GenericAdapter struct{}

// genericInput supports various tool name field conventions.
type genericInput struct {
	ToolName  string          `json:"tool_name"`
	Tool      string          `json:"tool"`
	Input     json.RawMessage `json:"input"`
	ToolInput json.RawMessage `json:"tool_input"`
	Args      json.RawMessage `json:"args"`
	SessionID string          `json:"session_id"`
}

func (g *genericInput) resolveToolName() string {
	if g.ToolName != "" {
		return g.ToolName
	}
	return g.Tool
}

func (g *genericInput) resolveArgs() json.RawMessage {
	if len(g.Input) > 0 && string(g.Input) != "null" {
		return g.Input
	}
	if len(g.ToolInput) > 0 && string(g.ToolInput) != "null" {
		return g.ToolInput
	}
	if len(g.Args) > 0 && string(g.Args) != "null" {
		return g.Args
	}
	return nil
}

func (a *GenericAdapter) Name() string { return "generic" }

// Detect always returns true — GenericAdapter is the terminal fallback.
func (a *GenericAdapter) Detect(_ json.RawMessage) bool { return true }

func (a *GenericAdapter) ParseInput(raw json.RawMessage) (boundarylab.CheckRequest, error) {
	var inp genericInput
	if err := json.Unmarshal(raw, &inp); err != nil {
		return boundarylab.CheckRequest{}, fmt.Errorf("parse generic input: %w", err)
	}
	toolName := inp.resolveToolName()
	if toolName == "" {
		return boundarylab.CheckRequest{}, fmt.Errorf("no tool_name or tool field found in input")
	}
	return boundarylab.CheckRequest{
		Tool:            toolName,
		Args:            inp.resolveArgs(),
		SessionID:       inp.SessionID,
		SpawnToken:      os.Getenv("BOUNDARYLAB_SPAWN_TOKEN"),
		ParentSessionID: os.Getenv("BOUNDARYLAB_PARENT_SESSION_ID"),
		ProjectRoot:     os.Getenv("BOUNDARYLAB_PROJECT_ROOT"),
	}, nil
}

func (a *GenericAdapter) FormatOutput(resp boundarylab.CheckResponse, _ json.RawMessage) ([]byte, int) {
	specific := ClaudeCodeHookSpecific{}
	switch resp.Decision.Action {
	case boundarylab.ActionAllow:
		specific.PermissionDecision = "allow"
	case boundarylab.ActionDeny:
		specific.PermissionDecision = "deny"
		specific.PermissionDecisionReason = resp.Decision.Reason
	case boundarylab.ActionRequireApproval:
		specific.PermissionDecision = "ask"
		specific.PermissionDecisionReason = resp.Decision.Reason
	case boundarylab.ActionAudit:
		specific.PermissionDecision = "allow"
	default:
		specific.PermissionDecision = "deny"
		specific.PermissionDecisionReason = "unknown action"
	}

	out := ClaudeCodeHookOutput{HookSpecificOutput: specific}
	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}` + "\n"), 2
	}
	exitCode := 0
	if specific.PermissionDecision != "allow" {
		exitCode = 2
	}
	return append(b, '\n'), exitCode
}

func (a *GenericAdapter) FormatFailClosed(reason string, _ json.RawMessage) ([]byte, int) {
	out := ClaudeCodeHookOutput{
		HookSpecificOutput: ClaudeCodeHookSpecific{
			PermissionDecision:       "deny",
			PermissionDecisionReason: fmt.Sprintf("fail-closed: %s", reason),
		},
	}
	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}` + "\n"), 2
	}
	return append(b, '\n'), 2
}
