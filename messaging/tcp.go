package messaging

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func CreateTCPHandler(ctx context.Context, host string, protocol string, stream quic.Stream) {

	listener, err := net.Listen(protocol, host)
	if err != nil {
		panic(err)
	}

	// loop through the listener and start capturing packets.
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping TCP handler.")
			return
		default:
			// Open a new stream
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						log.Printf("Error accepting connection: %v", err)
						continue
					}
					go proxyTCPToQUIC(conn, stream) // Handle connection asynchronously
				}
			}()
			if err != nil {
				if ctx.Err() != nil {
					fmt.Println("Connection shutting down.")
					return
				}
				log.Printf("Error TCP handler: %v", err)
				time.Sleep(2 * time.Second) // Backoff before retrying
				continue
			}
		}
	}

}

// Proxy TCP <--> QUIC transparently
func proxyTCPToQUIC(conn net.Conn, stream quic.Stream) {
	defer conn.Close()
	defer stream.Close()

	go func() {
		_, err := io.Copy(stream, conn) // TCP -> QUIC
		if err != nil {
			log.Printf("Error copying from TCP to QUIC: %v", err)
		}
	}()

	_, err := io.Copy(conn, stream) // QUIC -> TCP
	if err != nil {
		log.Printf("Error copying from QUIC to TCP: %v", err)
	}
}

// Example of handling QUIC connections
func handleQUICConnection(quicConn quic.Connection, tcpAddr string) {
	for {
		stream, err := quicConn.AcceptStream(nil) // Accept a new QUIC stream
		if err != nil {
			log.Printf("Error accepting QUIC stream: %v", err)
			return
		}

		// Dial a new TCP connection
		tcpConn, err := net.Dial("tcp", tcpAddr)
		if err != nil {
			log.Printf("Failed to connect to TCP target %s: %v", tcpAddr, err)
			stream.Close()
			continue
		}

		fmt.Printf("Proxying QUIC <-> TCP (%s)\n", tcpAddr)

		// Start proxying between TCP and QUIC
		go proxyTCPToQUIC(tcpConn, stream)
	}
}
