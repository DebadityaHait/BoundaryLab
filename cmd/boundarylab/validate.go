// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"fmt"

	"boundarylab.local/boundarylab/internal/bundle"
	"boundarylab.local/boundarylab/internal/cel"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate <policy-dir>",
	Short: "Validate policy YAML files and CEL expressions",
	Args:  cobra.ExactArgs(1),
	RunE:  runValidate,
}

func runValidate(cmd *cobra.Command, args []string) error {
	dir := args[0]
	templates, _, err := bundle.ParsePolicyDir(dir)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	if len(templates) == 0 {
		return fmt.Errorf("no policies found in %s", dir)
	}

	env, err := cel.NewCELEnvironment()
	if err != nil {
		return err
	}
	_, _, err = cel.CompileAll(env, templates)
	if err != nil {
		var compErr *cel.CompileError
		if errors.As(err, &compErr) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s:%d: %s\n",
				compErr.SourceFile, compErr.SourceLine, compErr.Cause)
			return fmt.Errorf("validation failed")
		}
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK: %d policies valid\n", len(templates))
	return nil
}
