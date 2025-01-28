package messaging

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func MonitorTCPHealth(ctx context.Context, request QuicMessage) net.Conn {
	var tcpConn net.Conn
	var err error

	// Retry loop for maintaining TCP connection
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping TCP health monitor.")
			if tcpConn != nil {
				tcpConn.Close()
			}
			return nil
		default:
			// Try connecting to the TCP host
			tcpConn, err = net.Dial("tcp", request.RemoteHost)
			if err != nil {
				log.Printf("TCP server (%s) is down. Retrying in 5 seconds...", request.RemoteHost)
				time.Sleep(5 * time.Second) // ✅ Wait before retrying
				continue
			}

			fmt.Printf("Connected to TCP server (%s)\n", request.RemoteHost)
			return tcpConn // ✅ Return the working connection
		}
	}
}

// ✅ Ensure TCP Handler Keeps Accepting Connections
func TCPHandler(ctx context.Context, lhost QuicMessage, rhost string, qcon quic.Connection) {

	listener, err := net.Listen("tcp", lhost.ClientHost)
	if err != nil {
		log.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	log.Printf("TCP Server listening on %s", lhost.ClientHost)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping TCP listener.")
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					fmt.Println("TCP listener shutting down.")
					return
				}
				log.Printf("Error accepting TCP connection: %v", err)
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				proxyTCPToQUIC(ctx, conn, qcon, lhost, rhost)
			}(conn)
		}
	}
}

// ✅ Forward TCP Data to QUIC
func proxyTCPToQUIC(ctx context.Context, conn net.Conn, qcon quic.Connection, lhost QuicMessage, rhost string) {
	defer conn.Close()
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping TCP handler.")
			return
		default:
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Printf("Client %s disconnected.\n", qcon.RemoteAddr())
				return
			}
			log.Printf("Sending upstream Lhost: %s, Rhost: %s", lhost, rhost)
			HandleUpStream(ctx, qcon, lhost, rhost, buf[:n])
		}
	}
}

// ✅ Handle QUIC → TCP Mapping
func QuicListenerHandler(ctx context.Context, listener quic.Listener, request QuicMessage) {
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping Remote TCP Handler.")
			return
		default:
			// ✅ Run `listener.Accept(ctx)` inside a separate goroutine
			go func() {
				qcon, err := listener.Accept(ctx)
				if err != nil {
					if ctx.Err() != nil {
						fmt.Println("Shutting down QUIC listener.")
						return
					}
					log.Printf("Error accepting QUIC connection: %v", err)
					return
				}

				// ✅ Handle each QUIC connection in a new goroutine
				go func(qcon quic.Connection, req QuicMessage) {
					log.Printf("PreRemote Handler %+v", req)
					RemoteTCPHandler(ctx, qcon, req)
				}(qcon, request)
			}()
		}
	}
}

// ✅ Handle Incoming QUIC Data and Write to TCP
func RemoteTCPHandler(ctx context.Context, qcon quic.Connection, request QuicMessage) {
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping Remote TCP Handler.")
			return
		default:
			// ✅ Accept QUIC stream
			stream, err := qcon.AcceptStream(ctx)
			if err != nil {
				if ctx.Err() != nil {
					fmt.Println("Remote TCP Handler shutting down.")
					return
				}
				log.Printf("Error accepting QUIC stream: %v", err)
				continue
			}

			// ✅ Parse QUIC message
			apikey := os.Getenv("API_KEY")
			request, err := ReadJSON(stream, apikey)
			if err != nil {
				log.Printf("Error parsing Stream RemoteTCP handler: %v", err)
				continue
			}

			fmt.Printf("Connected QUIC streamID: %+v to TCP server (%s)\n", request.StreamID, request.RemoteHost)

			// ✅ Write received QUIC data to TCP connection
			// _, err = tcpConn.Write(request.Data)
			// if err != nil {
			// 	log.Printf("Error writing to TCP connection: %v", err)
			// 	return
			// }
		}
	}
}
