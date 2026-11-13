package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/BudEcosystem/budctl/internal/cli"
)

func main() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := cli.NewDefaultCommand().ExecuteContext(ctx)
	stop()

	os.Exit(cli.ExitCode(err))
}
