package cmd

import (
	"elevpn/internal/client"
	"fmt"

	"github.com/spf13/cobra"
)

type clientOptions struct {
	ListenAddr     string
	ServerEndpoint string
	TunName        string
	TunAddrCIDR    string
}

var clientOpts = clientOptions{}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run elevpn in client mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		if verbose {
			fmt.Println("[client] verbose enabled")
		}
		fmt.Printf("[client] listen=%s endpoint=%s tunName=%s tunCIDR=%s\n",
			clientOpts.ListenAddr, clientOpts.ServerEndpoint, clientOpts.TunName, clientOpts.TunAddrCIDR,
		)

		cli, err := client.New(client.ClientConfig{
			ListenAddr:     clientOpts.ListenAddr,
			ServerEndpoint: clientOpts.ServerEndpoint,
			TunName:        clientOpts.TunName,
			TunAddrCIDR:    clientOpts.TunAddrCIDR,
		})
		if err != nil {
			return err
		}

		return cli.Run(cmd.Context())
	},
}

func init() {
	clientCmd.Flags().StringVar(&clientOpts.ListenAddr, "listen", ":0", "elevpn local UDP address")
	clientCmd.Flags().StringVar(&clientOpts.ServerEndpoint, "server-endpoint", "0.0.0.0:9010", "elevpn endpoint UDP address")
	clientCmd.Flags().StringVar(&clientOpts.TunName, "tun", "tun1", "TUN device name")
	clientCmd.Flags().StringVar(&clientOpts.TunAddrCIDR, "tun-cidr", "10.77.0.2/32", "TUN interface CIDR (client)")
	// _ = clientCmd.MarkFlagRequired("server")  로컬 테스트를 위해서 잠시 주석처리
}
