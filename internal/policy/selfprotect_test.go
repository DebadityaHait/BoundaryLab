// SPDX-License-Identifier: MIT
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"boundarylab.local/boundarylab/pkg/boundarylab"
)

func TestSelfProtectGuard_AllowedRequests(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		{name: "shell ls", tool: "Shell", args: map[string]any{"command": "ls"}},
		{name: "write to tmp", tool: "Write", args: map[string]any{"path": "/tmp/foo.txt"}},
		{name: "shell git status", tool: "Shell", args: map[string]any{"command": "git status"}},
		{name: "read boundarylab file allowed", tool: "Read", args: map[string]any{"path": "/Users/test/.boundarylab/policies/builtin/foo.yaml"}},
		{name: "shell echo to normal file", tool: "Bash", args: map[string]any{"command": "echo hello > /tmp/out.txt"}},
		{name: "shell kill other process", tool: "Bash", args: map[string]any{"command": "kill 12345"}},
		{name: "write to project file", tool: "Write", args: map[string]any{"path": "/home/user/project/src/main.go"}},
		{name: "shell npm install", tool: "Shell", args: map[string]any{"command": "npm install express"}},
		{name: "shell rm normal file", tool: "Bash", args: map[string]any{"command": "rm /tmp/foo.txt"}},
		{name: "empty args write", tool: "Write", args: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var argsJSON json.RawMessage
			if tt.args != nil {
				argsJSON, _ = json.Marshal(tt.args)
			}
			req := boundarylab.CheckRequest{Tool: tt.tool, Args: argsJSON}
			decision := g.Check(req)
			if decision != nil {
				t.Errorf("expected allow (nil), got deny: %s", decision.Reason)
			}
		})
	}
}

func TestSelfProtectGuard_BlocksFileWrites(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()
	home, _ := os.UserHomeDir()

	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		{
			name: "write to boundarylab policy builtin",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".boundarylab/policies/builtin/x.yaml")},
		},
		{
			name: "write to boundarylab hook binary",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".boundarylab/boundarylab-hook")},
		},
		{
			name: "write to settings.json",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".claude/settings.json")},
		},
		{
			name: "write to launchd plist",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, "Library/LaunchAgents/com.boundarylab.daemon.plist")},
		},
		{
			name: "write to systemd service",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".config/systemd/user/boundarylab-daemon.service")},
		},
		{
			name: "delete boundarylab hook",
			tool: "Delete",
			args: map[string]any{"path": filepath.Join(home, ".boundarylab/boundarylab-hook")},
		},
		{
			name: "edit boundarylab policy",
			tool: "Edit",
			args: map[string]any{"path": filepath.Join(home, ".boundarylab/policies/builtin/self-protection.yaml")},
		},
		{
			name: "str_replace settings",
			tool: "StrReplace",
			args: map[string]any{"path": filepath.Join(home, ".claude/settings.json")},
		},
		{
			name: "multi_edit boundarylab config",
			tool: "MultiEdit",
			args: map[string]any{"target_file": filepath.Join(home, ".boundarylab/config.yaml")},
		},
		{
			name: "tilde path write",
			tool: "Write",
			args: map[string]any{"path": "~/.boundarylab/policies/custom/evil.yaml"},
		},
		{
			name: "HOME var path write",
			tool: "Write",
			args: map[string]any{"path": "$HOME/.boundarylab/policies/x.yaml"},
		},
		{
			name: "tilde settings write",
			tool: "Write",
			args: map[string]any{"path": "~/.claude/settings.json"},
		},
		{
			name: "HOME var settings write",
			tool: "Write",
			args: map[string]any{"path": "$HOME/.claude/settings.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			argsJSON, _ := json.Marshal(tt.args)
			req := boundarylab.CheckRequest{Tool: tt.tool, Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Fatal("expected deny, got allow (nil)")
			}
			if decision.Action != boundarylab.ActionDeny {
				t.Errorf("expected ActionDeny, got %v", decision.Action)
			}
			if decision.PolicyID != "boundarylab-self-protection-guard" {
				t.Errorf("expected PolicyID 'boundarylab-self-protection-guard', got %q", decision.PolicyID)
			}
			if decision.Reason != selfProtectDenyReason {
				t.Errorf("unexpected reason: %s", decision.Reason)
			}
		})
	}
}

func TestSelfProtectGuard_BlocksShellCommands(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	tests := []struct {
		name    string
		command string
	}{
		{name: "kill pgrep boundarylab", command: "kill $(pgrep boundarylab)"},
		{name: "kill pgrep boundarylab-daemon", command: "kill $(pgrep boundarylab-daemon)"},
		{name: "pkill boundarylab-daemon", command: "pkill -9 boundarylab-daemon"},
		{name: "killall boundarylab-daemon", command: "killall boundarylab-daemon"},
		{name: "launchctl bootout", command: "launchctl bootout gui/501 com.boundarylab.daemon"},
		{name: "launchctl unload", command: "launchctl unload ~/Library/LaunchAgents/com.boundarylab.daemon.plist"},
		{name: "launchctl remove", command: "launchctl remove com.boundarylab.daemon"},
		{name: "systemctl stop", command: "systemctl --user stop boundarylab-daemon"},
		{name: "systemctl disable", command: "systemctl --user disable boundarylab-daemon"},
		{name: "systemctl mask", command: "systemctl --user mask boundarylab-daemon"},
		{name: "rm boundarylab dir", command: "rm -rf ~/.boundarylab/"},
		{name: "rm boundarylab hook", command: "rm ~/.boundarylab/boundarylab-hook"},
		{name: "mv boundarylab hook", command: "mv ~/.boundarylab/boundarylab-hook /tmp/"},
		{name: "chmod boundarylab hook", command: "chmod 000 ~/.boundarylab/boundarylab-hook"},
		{name: "chown boundarylab dir", command: "chown root:root ~/.boundarylab/"},
		{name: "boundarylab daemon stop", command: "boundarylab daemon stop"},
		{name: "boundarylab daemon restart", command: "boundarylab daemon restart"},
		{name: "boundarylab setup uninstall", command: "boundarylab setup --uninstall"},
		{name: "echo redirect to boundarylab", command: "echo 'exit 0' > ~/.boundarylab/boundarylab-hook"},
		{name: "tee to boundarylab", command: "echo '' | tee ~/.boundarylab/policies/builtin/allow-all.yaml"},
		{name: "sed on settings", command: "sed -i '' '/hooks/d' ~/.claude/settings.json"},
		{name: "crontab boundarylab kill", command: "echo '* * * * * kill $(pgrep boundarylab-daemon)' | crontab -"},
		{name: "crontab rm boundarylab", command: "crontab -l | echo '0 0 * * * rm -rf ~/.boundarylab' | crontab -"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			argsJSON, _ := json.Marshal(map[string]string{"command": tt.command})
			req := boundarylab.CheckRequest{Tool: "Bash", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Fatalf("command %q: expected deny, got allow", tt.command)
			}
			if decision.Action != boundarylab.ActionDeny {
				t.Errorf("expected ActionDeny, got %v", decision.Action)
			}
		})
	}
}

func TestSelfProtectGuard_EvasionAttempts(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()
	home, _ := os.UserHomeDir()

	t.Run("symlink to protected dir", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		symlinkPath := filepath.Join(tmpDir, "innocent-link")
		targetPath := filepath.Join(home, ".boundarylab", "policies")

		if _, err := os.Stat(targetPath); err == nil {
			if err := os.Symlink(targetPath, symlinkPath); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}

			argsJSON, _ := json.Marshal(map[string]string{"path": filepath.Join(symlinkPath, "evil.yaml")})
			req := boundarylab.CheckRequest{Tool: "Write", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Error("symlink evasion to .boundarylab/policies/: expected deny, got allow")
			}
		} else {
			t.Skip("target path does not exist")
		}
	})

	t.Run("symlink to settings.json", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		symlinkPath := filepath.Join(tmpDir, "link-to-settings")
		targetPath := filepath.Join(home, ".claude", "settings.json")

		if _, err := os.Stat(targetPath); err == nil {
			if err := os.Symlink(targetPath, symlinkPath); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}

			argsJSON, _ := json.Marshal(map[string]string{"path": symlinkPath})
			req := boundarylab.CheckRequest{Tool: "Write", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Error("symlink evasion to settings.json: expected deny, got allow")
			}
		} else {
			t.Skip("target path does not exist")
		}
	})

	t.Run("path with HOME env var", func(t *testing.T) {
		t.Parallel()
		argsJSON, _ := json.Marshal(map[string]string{"path": "$HOME/.boundarylab/policies/x.yaml"})
		req := boundarylab.CheckRequest{Tool: "Write", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("$HOME evasion: expected deny, got allow")
		}
	})

	t.Run("path with tilde", func(t *testing.T) {
		t.Parallel()
		argsJSON, _ := json.Marshal(map[string]string{"path": "~/.boundarylab/policies/x.yaml"})
		req := boundarylab.CheckRequest{Tool: "Write", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("tilde evasion: expected deny, got allow")
		}
	})

	t.Run("cron injection to kill boundarylab", func(t *testing.T) {
		t.Parallel()
		cmd := "echo '* * * * * kill $(pgrep boundarylab-daemon)' | crontab -"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := boundarylab.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cron injection evasion: expected deny, got allow")
		}
	})

	t.Run("indirect git checkout in boundarylab dir", func(t *testing.T) {
		t.Parallel()
		cmd := "cd ~/.boundarylab/policies && git checkout -- ."
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := boundarylab.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("git checkout evasion in .boundarylab/: expected deny, got allow")
		}
	})

	t.Run("indirect git reset in boundarylab dir", func(t *testing.T) {
		t.Parallel()
		cmd := "git reset --hard HEAD -- ~/.boundarylab/policies/"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := boundarylab.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("git reset evasion targeting .boundarylab/: expected deny, got allow")
		}
	})

	t.Run("pipe to overwrite boundarylab file", func(t *testing.T) {
		t.Parallel()
		cmd := "cat /dev/null > ~/.boundarylab/config.yaml"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := boundarylab.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cat redirect evasion: expected deny, got allow")
		}
	})

	t.Run("cp overwrite to boundarylab sock", func(t *testing.T) {
		t.Parallel()
		cmd := "cp /dev/null ~/.boundarylab/boundarylab.sock"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := boundarylab.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cp to boundarylab.sock evasion: expected deny, got allow")
		}
	})

	t.Run("truncate boundarylab config", func(t *testing.T) {
		t.Parallel()
		cmd := "truncate -s 0 ~/.boundarylab/config.yaml"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := boundarylab.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("truncate evasion: expected deny, got allow")
		}
	})

	t.Run("com.boundarylab.daemon in launchctl remove", func(t *testing.T) {
		t.Parallel()
		cmd := "launchctl remove com.boundarylab.daemon"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := boundarylab.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("launchctl remove com.boundarylab.daemon: expected deny, got allow")
		}
	})
}

func TestSelfProtectGuard_NonShellToolsNotBlocked(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	req := boundarylab.CheckRequest{
		Tool: "Read",
		Args: json.RawMessage(`{"path":"/Users/test/.boundarylab/policies/builtin/foo.yaml"}`),
	}
	decision := g.Check(req)
	if decision != nil {
		t.Error("Read tool should not be blocked by self-protection")
	}
}

func TestSelfProtectGuard_EmptyArgs(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	req := boundarylab.CheckRequest{Tool: "Write", Args: nil}
	decision := g.Check(req)
	if decision != nil {
		t.Error("nil args should not trigger self-protection")
	}
}

func TestSelfProtectGuard_DecisionFields(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()
	home, _ := os.UserHomeDir()

	argsJSON, _ := json.Marshal(map[string]string{"path": filepath.Join(home, ".boundarylab/config.yaml")})
	req := boundarylab.CheckRequest{Tool: "Write", Args: argsJSON}
	decision := g.Check(req)
	if decision == nil {
		t.Fatal("expected deny decision")
	}

	if decision.Action != boundarylab.ActionDeny {
		t.Errorf("Action = %v, want ActionDeny", decision.Action)
	}
	if decision.PolicyID != "boundarylab-self-protection-guard" {
		t.Errorf("PolicyID = %q, want 'boundarylab-self-protection-guard'", decision.PolicyID)
	}
	if decision.Reason != selfProtectDenyReason {
		t.Errorf("Reason = %q, want %q", decision.Reason, selfProtectDenyReason)
	}
}

func BenchmarkSelfProtectGuard_Allow(b *testing.B) {
	g := NewSelfProtectGuard()
	argsJSON, _ := json.Marshal(map[string]string{"command": "ls -la /tmp"})
	req := boundarylab.CheckRequest{Tool: "Bash", Args: argsJSON}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check(req)
	}
}

func BenchmarkSelfProtectGuard_Deny(b *testing.B) {
	g := NewSelfProtectGuard()
	argsJSON, _ := json.Marshal(map[string]string{"command": "rm -rf ~/.boundarylab/"})
	req := boundarylab.CheckRequest{Tool: "Bash", Args: argsJSON}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check(req)
	}
}
