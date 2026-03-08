package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose bool
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "elevpn",
	Short: "elevpn is a simple TUN-over-UDP VPN",
	Long:  "elevpn provides a server/client mode VPN using a TUN device and UDP transport",
}

func Execute(ctx context.Context) {
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")

	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(clientCmd)
}
