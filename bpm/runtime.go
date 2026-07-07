package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

const defaultCommandTimeout = 30 * time.Second

var version = "dev"

func commandContext(cmd *cobra.Command) (context.Context, context.CancelFunc, error) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithTimeout(parent, defaultCommandTimeout)
	return ctx, cancel, nil
}
