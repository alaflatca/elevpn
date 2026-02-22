package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v", err)
		os.Exit(1)
	}

}

func run(ctx context.Context) error {
	return nil
}
