package cmd

import (
	"elevpn/internal/server"
	"fmt"

	"github.com/spf13/cobra"
)

type serverOptions struct {
	ListenAddr     string
	TunName        string
	TunAddrCIDR    string
	VPNNetworkCIDR string
}

var serverOpts = serverOptions{}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run elevpn in server mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		if verbose {
			fmt.Println("[server] verbose enabled")
		}
		fmt.Printf("[server] init listen=%s tun-name=%s tun-addr-cidr=%s vpn-network-cidr=%s\n", serverOpts.ListenAddr, serverOpts.TunName, serverOpts.TunAddrCIDR, serverOpts.VPNNetworkCIDR)

		svr, err := server.New(server.ServerConfig{
			ListenAddr:     serverOpts.ListenAddr,
			TunName:        serverOpts.TunName,
			TunAddrCIDR:    serverOpts.TunAddrCIDR,
			VPNNetworkCIDR: serverOpts.VPNNetworkCIDR,
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
	serverCmd.Flags().StringVar(&serverOpts.ListenAddr, "listen", "0.0.0.0:9010", "UDP listen address")
	serverCmd.Flags().StringVar(&serverOpts.TunName, "tun-name", "tun0", "TUN device name")
	serverCmd.Flags().StringVar(&serverOpts.TunAddrCIDR, "tun-addr-cidr", "10.77.0.1/24", "TUN interface CIDR (server)")
	serverCmd.Flags().StringVar(&serverOpts.VPNNetworkCIDR, "vpn-network-cidr", "10.77.0.0/24", "VPN Network CIDR (server)")
}
