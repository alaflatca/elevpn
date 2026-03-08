package main

import (
	"context"
	"elevpn/cmd"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.TODO(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd.Execute(ctx)
}
