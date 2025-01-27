package client

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	qmsg "quic-tunnel/messaging"

	"github.com/quic-go/quic-go"
)

var (
	tlsconf = generateTLSConfig()
	cert    = tlsconf.Certificates[0]

	// API Key (Secret Key) - Should be securely stored
	API_KEY = "supersecretapikey"

	// The client hosts
	clientconf = qmsg.ParseClientConfigs(API_KEY, "localhost:8080/tcp,localhost:8081/tcp")
	// The upstream hosts to connect to
	remoteconf = qmsg.ParseClientConfigs(API_KEY, "localhost:8084/tcp,localhost:8085/tcp")
)

// ** Client: Connects to QUIC Server and Listens on TCP Ports **
func Client(ctx context.Context, wg *sync.WaitGroup) {

	defer wg.Done()
	quicConfig := &quic.Config{
		MaxIdleTimeout:  45 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
	}

	conn, err := quic.DialAddr(ctx, "localhost:4242", tlsconf, quicConfig)
	if err != nil {
		log.Fatalf("Failed to connect to QUIC server: %v", err)
	}
	fmt.Println("Client connected to QUIC server...")

	go func() {
		<-ctx.Done()
		fmt.Println("Shutting down client...")
		conn.CloseWithError(0, "Client shutting down")
	}()

	wg.Add(len(clientconf))
	for i, host := range clientconf {
		select {
		case <-ctx.Done():
			fmt.Println("Client stopping new connections.")
			return
		default:
			go func(i int, lhost qmsg.QuicMessage) {
				defer wg.Done() // Ensure counter is decremented
				rhost := remoteconf[i].ClientHost
				qmsg.HandleStream(ctx, conn, i, lhost, rhost)
			}(i, host)
		}
	}

}
