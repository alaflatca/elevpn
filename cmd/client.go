package cmd

import (
	"elevpn/internal/client"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	clientAddr   string
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
		fmt.Printf("[client] addr=%s server=%s tun=%s cidr=%s\n", clientAddr, clientServer, clientTun, clientCIDR)

		cli, err := client.New(client.ClientConfig{
			Addr:       clientAddr,
			ServerAddr: clientServer,
			TunName:    clientTun,
			CIDR:       clientCIDR,
		})
		if err != nil {
			return err
		}
		if err := cli.Run(cmd.Context()); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	clientCmd.Flags().StringVar(&clientAddr, "addr", "127.0.0.1:8888", "elevpn local UDP address")
	clientCmd.Flags().StringVar(&clientServer, "server", "127.0.0.1:7777", "elevpn server UDP address")
	clientCmd.Flags().StringVar(&clientTun, "tun", "tun0", "TUN device name")
	clientCmd.Flags().StringVar(&clientCIDR, "cidr", "10.8.0.2/24", "TUN interface CIDR (client)")
}
