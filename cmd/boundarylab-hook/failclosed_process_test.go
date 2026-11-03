package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailClosedHookProcess(t *testing.T) {
	if os.Getenv("BOUNDARYLAB_HOOK_TEST_HELPER") == "1" {
		main()
		return
	}
	for _, tc := range []struct {
		name, input, field, want string
		exit                     int
	}{
		{"claude daemon unavailable", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "hookSpecificOutput", "deny", 0},
		{"cursor daemon unavailable", `{"conversation_id":"s1","tool_name":"Bash","input":{"command":"echo ok"}}`, "decision", "deny", 2},
		{"malformed input", `{bad`, "hookSpecificOutput", "deny", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestFailClosedHookProcess$")
			cmd.Env = append(os.Environ(), "BOUNDARYLAB_HOOK_TEST_HELPER=1", "BOUNDARYLAB_SOCKET_PATH="+filepath.Join(t.TempDir(), "missing.sock"), "BOUNDARYLAB_FAILCLOSED_LOG="+filepath.Join(t.TempDir(), "events.log"), "BOUNDARYLAB_OTEL_ENDPOINT=")
			cmd.Stdin = strings.NewReader(tc.input)
			out, err := cmd.Output()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.exit {
				t.Fatalf("exit=%d want %d: %s", code, tc.exit, out)
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(out, &envelope); err != nil {
				t.Fatalf("invalid response %q: %v", out, err)
			}
			var nested map[string]any
			if err := json.Unmarshal(envelope[tc.field], &nested); err != nil {
				t.Fatal(err)
			}
			decision := nested["permissionDecision"]
			if tc.field == "decision" {
				decision = nested["action"]
			}
			if decision != tc.want {
				t.Fatalf("decision=%v, response=%s", decision, out)
			}
		})
	}
}

func TestHookRejectsInvalidDaemonResponse(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "daemon.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		var header [4]byte
		if _, err = io.ReadFull(conn, header[:]); err != nil {
			serverDone <- err
			return
		}
		payload := make([]byte, binary.BigEndian.Uint32(header[:]))
		if _, err = io.ReadFull(conn, payload); err != nil {
			serverDone <- err
			return
		}
		_, err = conn.Write([]byte{0, 0, 0, 3, 'b', 'a', 'd'})
		serverDone <- err
	}()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFailClosedHookProcess$")
	cmd.Env = append(os.Environ(), "BOUNDARYLAB_HOOK_TEST_HELPER=1", "BOUNDARYLAB_SOCKET_PATH="+socket, "BOUNDARYLAB_FAILCLOSED_LOG="+filepath.Join(t.TempDir(), "events.log"), "BOUNDARYLAB_OTEL_ENDPOINT=")
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err = json.Unmarshal(out, &result); err != nil || result.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("expected deny, got %s, %v", out, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
