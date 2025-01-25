package main

import (
	"fmt"
	"os"
	"strings"

	client "quic-tunnel/client"
	"quic-tunnel/logger"
	"quic-tunnel/models"
	serv "quic-tunnel/server"

	"github.com/spf13/cobra"
)

var (
	logd = logger.Loger
)

// parseUpstreams parses `--upstreams` into a list of Upstream structs
func parseUpstreams(upstreamStr string) ([]models.Upstream, error) {
	var upstreams []models.Upstream

	if upstreamStr == "" {
		return nil, fmt.Errorf("⚠️ no upstreams provided, use --upstreams to specify at least one upstream")
	}

	entries := strings.Split(upstreamStr, ",")
	for _, entry := range entries {
		parts := strings.Split(entry, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("⚠️ invalid upstream format: %s (expected IP:port/protocol)", entry)
		}

		addrParts := strings.Split(parts[0], ":")
		if len(addrParts) != 2 {
			return nil, fmt.Errorf("⚠️ invalid address format: %s (expected IP:port)", parts[0])
		}

		upstream := models.Upstream{
			Address:  addrParts[0],
			Port:     addrParts[1],
			Protocol: parts[1],
		}
		upstreams = append(upstreams, upstream)
	}

	return upstreams, nil
}

// servCmd represents the command to start the server
var servCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the QUIC tunnel server",
	Run: func(cmd *cobra.Command, args []string) {
		server, _ := cmd.Flags().GetString("server")
		port, _ := cmd.Flags().GetString("port")
		upstreamsStr, _ := cmd.Flags().GetString("upstreams")

		// Validate and parse upstreams
		upstreams, err := parseUpstreams(upstreamsStr)
		if err != nil {
			logd.Fatal("⚠️ Error: %v\n\nUsage:\n  %s\n", err, cmd.UsageString())
		}

		// Print parsed upstreams
		for _, up := range upstreams {
			logd.Info("✅ Parsed Upstream -> Address: %s, Port: %s, Protocol: %s\n", up.Address, up.Port, up.Protocol)
		}

		// Ensure server flag is set
		if server == "" {
			logd.Info("⚠️ Server address is required. Use --server to specify it.")
			fmt.Println(cmd.UsageString())
			os.Exit(1)
		}

		// Start the server
		serv.Startserver(server, port, upstreams)
	},
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Starts the QUIC tunnel client",
	Run: func(cmd *cobra.Command, args []string) {
		server, _ := cmd.Flags().GetString("server")
		port, _ := cmd.Flags().GetString("port")
		serverAddr := server + ":" + port
		// Ensure server flag is set
		if server == "" {
			logd.Info("⚠️ Server address is required. Use --server to specify it.")
			fmt.Println(cmd.UsageString())
			os.Exit(1)
		}

		// Start the server
		client.Startclient(serverAddr)
	},
}

func main() {
	// Define root Cobra command
	rootCmd := &cobra.Command{Use: "quic-tunnel"}

	// Add flags for server command
	servCmd.Flags().String("server", "", "Server address (e.g., localhost or 0.0.0.0)")
	servCmd.Flags().String("port", "4368", "Port number")
	servCmd.Flags().String("upstreams", "", "Comma-separated list of upstreams (e.g., 192.168.1.1:8080/tcp,192.168.1.2:53/udp)")

	// Add flags for client command
	clientCmd.Flags().String("server", "", "Server address (e.g., localhost or 0.0.0.0)")
	clientCmd.Flags().String("port", "4368", "Port number")

	// Mark --server and --upstreams as required for server
	_ = servCmd.MarkFlagRequired("server")
	_ = servCmd.MarkFlagRequired("upstreams")

	// Mark --server and --port as required for client
	_ = clientCmd.MarkFlagRequired("server")
	_ = clientCmd.MarkFlagRequired("port")

	// Add start command to root
	rootCmd.AddCommand(servCmd)
	rootCmd.AddCommand(clientCmd)

	// Execute the command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
