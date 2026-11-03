// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"boundarylab.local/boundarylab/pkg/boundarylab"
)

// ClaudeCodeAdapter handles the Claude Code hook protocol.
// Detection: presence of "hook_event_name" field in the input JSON.
type ClaudeCodeAdapter struct{}

// claudeCodeInput is the JSON shape sent by Claude Code hooks.
type claudeCodeInput struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

func (a *ClaudeCodeAdapter) Name() string { return "claude_code" }

func (a *ClaudeCodeAdapter) Detect(raw json.RawMessage) bool {
	var probe struct {
		HookEventName string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.HookEventName != ""
}

func (a *ClaudeCodeAdapter) ParseInput(raw json.RawMessage) (boundarylab.CheckRequest, error) {
	var inp claudeCodeInput
	if err := json.Unmarshal(raw, &inp); err != nil {
		return boundarylab.CheckRequest{}, fmt.Errorf("parse claude code input: %w", err)
	}
	return boundarylab.CheckRequest{
		Tool:            inp.ToolName,
		Args:            inp.ToolInput,
		SessionID:       inp.SessionID,
		SpawnToken:      os.Getenv("BOUNDARYLAB_SPAWN_TOKEN"),
		ParentSessionID: os.Getenv("BOUNDARYLAB_PARENT_SESSION_ID"),
		ProjectRoot:     os.Getenv("BOUNDARYLAB_PROJECT_ROOT"),
	}, nil
}

func (a *ClaudeCodeAdapter) FormatOutput(resp boundarylab.CheckResponse, rawInput json.RawMessage) ([]byte, int) {
	var inp struct {
		HookEventName string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(rawInput, &inp)

	specific := ClaudeCodeHookSpecific{
		HookEventName: inp.HookEventName,
	}
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
		return []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}` + "\n"), 0
	}
	return append(b, '\n'), 0
}

func (a *ClaudeCodeAdapter) FormatFailClosed(reason string, rawInput json.RawMessage) ([]byte, int) {
	var inp struct {
		HookEventName string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(rawInput, &inp)

	out := ClaudeCodeHookOutput{
		HookSpecificOutput: ClaudeCodeHookSpecific{
			HookEventName:            inp.HookEventName,
			PermissionDecision:       "deny",
			PermissionDecisionReason: fmt.Sprintf("fail-closed: %s", reason),
		},
	}
	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}` + "\n"), 0
	}
	return append(b, '\n'), 0
}
