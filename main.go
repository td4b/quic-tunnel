package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"quic-tunnel/client"
	"quic-tunnel/server"
	"sync"
)

func main() {

	ctx, cancel := context.WithCancel(context.Background())

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		<-sigChan
		fmt.Println("\nReceived shutdown signal, terminating...")
		cancel()
	}()

	go server.Server(ctx, &wg)
	go client.Client(ctx, &wg)

	wg.Wait() // Wait for the server to exit before main exits

	// Start QUIC listener

}
