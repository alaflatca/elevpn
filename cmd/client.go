package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	clientServer string
	clientTun    string
	clientCIDR   string
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run elevpn in client mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		if verbose {
			fmt.Println("[client] verbose enabled")
		}
		fmt.Printf("[client] server=%s tun=%s cidr=%s\n", clientServer, clientTun, clientCIDR)

		// TODO: internal/client.Run(...)

		return nil
	},
}

func init() {
	clientCmd.Flags().StringVar(&clientServer, "server", "127.0.0.1:51820", "elevpn server UDP address")
	clientCmd.Flags().StringVar(&clientTun, "tun", "tun0", "TUN device name")
	clientCmd.Flags().StringVar(&clientCIDR, "cidr", "10.8.0.2/24", "TUN interface CIDR (client)")
}
