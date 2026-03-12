package cmd

import (
	"elevpn/internal/client"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	clientListen    string
	clientServer    string
	clientTun       string
	clientTunListen string
	clientCIDR      string
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run elevpn in client mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		if verbose {
			fmt.Println("[client] verbose enabled")
		}
		fmt.Printf("[client] addr=%s server=%s tun=%s cidr=%s\n", clientListen, clientServer, clientTun, clientCIDR)

		cli, err := client.New(client.ClientConfig{
			Addr:       clientListen,
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
	clientCmd.Flags().StringVar(&clientListen, "listen", "0.0.0.0:9020", "elevpn local UDP address")
	clientCmd.Flags().StringVar(&clientServer, "server", "0.0.0.0:9010", "elevpn server UDP address")
	clientCmd.Flags().StringVar(&clientTun, "tun", "tun1", "TUN device name")
	clientCmd.Flags().StringVar(&clientCIDR, "cidr", "10.77.0.2/32", "TUN interface CIDR (client)")
	// _ = clientCmd.MarkFlagRequired("server")  로컬 테스트를 위해서 잠시 주석처리
}
