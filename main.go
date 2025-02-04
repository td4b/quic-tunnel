package main

import (
	"fmt"
	"os"
	client "quic-tunnel/client"
	"quic-tunnel/logger"
	serv "quic-tunnel/server"

	"github.com/spf13/cobra"
)

var (
	logd = logger.Loger
)

// servCmd represents the command to start the server
var servCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the QUIC tunnel server",
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
		serv.StartServer(serverAddr)
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
		client.StartClient(serverAddr)
	},
}

func main() {

	os.Setenv("DEBUG", "false")
	// Define root Cobra command
	rootCmd := &cobra.Command{Use: "quic-tunnel"}

	// Add flags for server command
	servCmd.Flags().String("server", "", "Server address (e.g., localhost or 0.0.0.0)")
	servCmd.Flags().String("port", "4222", "Port number")

	// Add flags for client command
	clientCmd.Flags().String("server", "", "Remote Server address.")
	clientCmd.Flags().String("port", "4222", "Port number")

	// Mark --server and --port required for server
	_ = servCmd.MarkFlagRequired("server")
	_ = servCmd.MarkFlagRequired("port")

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
