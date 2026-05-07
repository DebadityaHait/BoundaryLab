// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	uninstallYes   bool
	uninstallForce bool
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Completely remove BoundaryLab from this machine",
	Long: `Removes all BoundaryLab components: stops daemon, removes service,
unhooks from Claude Code/Cursor, deletes policies, removes PATH entry,
and cleans up ~/.boundarylab/.

This is the inverse of 'boundarylab setup'. Run it manually — AI agents
cannot execute this command (BoundaryLab blocks self-removal by policy).

If this command hangs, use --force to bypass service management:
  boundarylab uninstall --force --yes

Manual recovery (if even --force hangs):
  pgrep -f boundarylab | xargs kill -9 2>/dev/null
  rm -f ~/Library/LaunchAgents/com.boundarylab.daemon.plist
  rm -rf ~/.boundarylab && rm -f /tmp/boundarylab.sock`,
	RunE: runUninstallCmd,
}

func init() {
	uninstallCmd.Flags().BoolVarP(&uninstallYes, "yes", "y", false, "Skip confirmation prompt")
	uninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "Skip service management (use when launchctl/systemctl is stuck)")
}

func runUninstallCmd(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	boundarylabDir := filepath.Join(homeDir, ".boundarylab")

	fmt.Fprintln(w, "BoundaryLab Uninstall")
	fmt.Fprintln(w, "===============")
	fmt.Fprintln(w)

	// Show what will be removed
	fmt.Fprintln(w, "This will remove:")
	fmt.Fprintf(w, "  • Daemon service and process\n")
	fmt.Fprintf(w, "  • Hook from ~/.claude/settings.json\n")
	fmt.Fprintf(w, "  • PATH entries from shell configs\n")
	fmt.Fprintf(w, "  • Socket at /tmp/boundarylab.sock\n")
	fmt.Fprintf(w, "  • Directory %s\n", boundarylabDir)
	fmt.Fprintln(w)

	if !uninstallYes {
		if !confirm("Proceed with uninstall?") {
			fmt.Fprintln(w, "Aborted.")
			return nil
		}
		fmt.Fprintln(w)
	}

	// Step 1: Stop daemon
	fmt.Fprintln(w, "[1/6] Stopping daemon...")
	if uninstallForce {
		if p := findDaemonPID(); p > 0 {
			fmt.Fprintf(w, "  Force-killing daemon (PID %d)...\n", p)
			_ = syscall.Kill(p, syscall.SIGKILL)
			time.Sleep(500 * time.Millisecond)
		} else {
			fmt.Fprintln(w, "  No daemon process found")
		}
	} else {
		if err := stopDaemonWithTimeout(5 * time.Second); err != nil {
			fmt.Fprintf(w, "  Warning: graceful stop failed (%v), force-killing...\n", err)
			if p := findDaemonPID(); p > 0 {
				_ = syscall.Kill(p, syscall.SIGKILL)
				time.Sleep(500 * time.Millisecond)
			}
		} else {
			fmt.Fprintln(w, "  Daemon stopped")
		}
	}

	// Step 2: Remove service definition
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[2/6] Removing service definition...")
	if err := uninstallDaemonService(); err != nil {
		fmt.Fprintf(w, "  Warning: %v\n", err)
	} else {
		fmt.Fprintln(w, "  Service removed")
	}

	// Step 3: Remove hook from settings.json
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[3/6] Removing hook from settings.json...")
	if err := unpatchSettingsJSON(w, homeDir); err != nil {
		fmt.Fprintf(w, "  Warning: %v\n", err)
	}

	// Step 4: Clean shell configs
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[4/6] Removing PATH entries from shell configs...")
	cleanShellConfigs(w, homeDir)

	// Step 5: Remove socket
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[5/6] Removing socket...")
	sockPath := "/tmp/boundarylab.sock"
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(w, "  Warning: could not remove %s: %v\n", sockPath, err)
	} else {
		fmt.Fprintf(w, "  Removed %s\n", sockPath)
	}

	// Step 6: Remove ~/.boundarylab/
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[6/6] Removing", boundarylabDir+"...")
	if err := os.RemoveAll(boundarylabDir); err != nil {
		fmt.Fprintf(w, "  Warning: %v\n", err)
	} else {
		fmt.Fprintln(w, "  Removed")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "✓ BoundaryLab uninstalled successfully.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To reinstall:")
	fmt.Fprintln(w, "  From your BoundaryLab checkout:")
	fmt.Fprintln(w, "  make build && ./bin/boundarylab setup")
	return nil
}

func cleanShellConfigs(w io.Writer, homeDir string) {
	configs := []string{
		filepath.Join(homeDir, ".zshrc"),
		filepath.Join(homeDir, ".bashrc"),
		filepath.Join(homeDir, ".profile"),
		filepath.Join(homeDir, ".config", "fish", "config.fish"),
	}
	for _, cfg := range configs {
		if removed := removeBoundaryLabLines(cfg); removed {
			fmt.Fprintf(w, "  Cleaned %s\n", cfg)
		}
	}
}

func removeBoundaryLabLines(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	var result []string
	modified := false
	skipNext := false

	for i, line := range lines {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.Contains(line, "# BoundaryLab") {
			// Also remove the blank line that install.sh writes immediately
			// before the marker (\n# BoundaryLab\n...). If the previous collected
			// line is blank, trim it.
			if len(result) > 0 && result[len(result)-1] == "" {
				result = result[:len(result)-1]
			}
			skipNext = true // skip the path/export line that follows
			modified = true
			_ = i // suppress unused warning
			continue
		}
		result = append(result, line)
	}

	if modified {
		_ = os.WriteFile(path, []byte(strings.Join(result, "\n")), 0o644)
	}
	return modified
}
