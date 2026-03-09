package cmd

import (
	"elevpn/internal/server"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	serverListen string
	serverTun    string
	serverCIDR   string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run elevpn in server mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		if verbose {
			fmt.Println("[server] verbose enabled")
		}
		fmt.Printf("[server] listen=%s tun=%s cidr=%s\n", serverListen, serverTun, serverCIDR)

		svr, err := server.New(server.ServerConfig{
			Addr:    serverListen,
			TunName: serverTun,
			CIDR:    serverCIDR,
		})
		if err != nil {
			return err
		}

		if err := svr.Run(cmd.Context()); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	serverCmd.Flags().StringVar(&serverListen, "listen", "127.0.0.1:7777", "UDP listen address")
	serverCmd.Flags().StringVar(&serverTun, "tun", "tun0", "TUN device name")
	serverCmd.Flags().StringVar(&serverCIDR, "cidr", "10.8.0.1/24", "TUN interface CIDR (server)")
	_ = clientCmd.MarkFlagRequired("server")
}
