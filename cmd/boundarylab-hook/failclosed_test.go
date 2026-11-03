package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHook_FailClosed_WritesLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "failclosed.log")

	now := time.Now()
	entry := FailClosedEntry{
		Ts:               now,
		Tool:             "Bash",
		SessionID:        "sess-123",
		Reason:           "daemon unreachable",
		DeadlineExceeded: false,
	}

	if err := writeFailClosed(logPath, entry); err != nil {
		t.Fatalf("writeFailClosed: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}

	var got FailClosedEntry
	if err := json.Unmarshal(bytes.TrimSpace(data), &got); err != nil {
		t.Fatalf("invalid JSON in log: %v\ncontents: %s", err, data)
	}

	if got.Tool != "Bash" {
		t.Errorf("tool = %q, want Bash", got.Tool)
	}
	if got.SessionID != "sess-123" {
		t.Errorf("sessionID = %q, want sess-123", got.SessionID)
	}
	if got.Reason != "daemon unreachable" {
		t.Errorf("reason = %q, want 'daemon unreachable'", got.Reason)
	}
	if got.Ts.IsZero() {
		t.Error("timestamp must be non-zero")
	}

	// Verify append: write a second entry and check both lines are present.
	entry2 := FailClosedEntry{
		Ts:        time.Now(),
		Tool:      "Write",
		SessionID: "sess-456",
		Reason:    "evaluation timeout",
	}
	if err := writeFailClosed(logPath, entry2); err != nil {
		t.Fatalf("second writeFailClosed: %v", err)
	}

	data2, _ := os.ReadFile(logPath)
	lines := bytes.Split(bytes.TrimSpace(data2), []byte("\n"))
	if len(lines) != 2 {
		t.Errorf("expected 2 log entries, got %d:\n%s", len(lines), data2)
	}
}
