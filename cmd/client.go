package cmd

import (
	"elevpn/internal/client"
	"log"

	"github.com/spf13/cobra"
)

type clientOptions struct {
	ListenAddr     string
	ServerEndpoint string
	TunName        string
}

var clientOpts = clientOptions{}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run elevpn in client mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		if verbose {
			log.Println("[init] verbose enabled")
		}
		log.Printf("[init] listen=%s endpoint=%s tunName=%s", clientOpts.ListenAddr, clientOpts.ServerEndpoint, clientOpts.TunName)

		cli, err := client.New(client.ClientConfig{
			ListenAddr:     clientOpts.ListenAddr,
			ServerEndpoint: clientOpts.ServerEndpoint,
			TunName:        clientOpts.TunName,
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
	// server-route-ip 는 endpoint 에서 가져와서 처리하는걸로
	// default gateway 값 필요함
	// real network interface 필요
	clientCmd.Flags().StringVar(&clientOpts.TunName, "tun", "tun0", "TUN device name")
	// _ = clientCmd.MarkFlagRequired("server")  로컬 테스트를 위해서 잠시 주석처리
}
