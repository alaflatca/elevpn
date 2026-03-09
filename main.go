package main

import (
	"context"
	"elevpn/cmd"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.TODO(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd.Execute(ctx)
}
