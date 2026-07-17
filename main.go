package main

import (
	"context"
	"elevpn/cmd"
	"log"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	start := time.Now()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd.Execute(ctx)

	log.Printf("uptime: %s", time.Since(start).String())
}
