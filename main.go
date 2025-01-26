package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
)

func main() {

	// Start QUIC listener

	go server()
	go client()

	// Wait indefinitely with proper signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Press Ctrl+C to exit...")
	<-sigs // Block until signal is received
	fmt.Println("Shutting down gracefully...")

}

// ** Secure 1:1 Mapping of QUIC streams to TCP upstreams **
var upstreamPorts = []int{8084, 8085} // Fixed mapping

// ** TCP client ports (client side) **
var clientPorts = []int{8080, 8081}

// ** Server: QUIC Server that relays traffic to TCP Upstream **
func server() {
	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second, // Ensures QUIC connection remains open
	}

	listener, err := quic.ListenAddr("localhost:4242", generateTLSConfig(), quicConfig)
	if err != nil {
		log.Fatalf("Failed to start QUIC server: %v", err)
	}
	fmt.Println("Server listening on port 4242...")

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept QUIC connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

// ** Handles a QUIC connection and relays data to TCP upstream **
func handleConnection(conn quic.Connection) {
	// Send fixed port mappings to the client
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("Failed to open initial QUIC stream: %v", err)
		return
	}

	portData, _ := json.Marshal(clientPorts)
	_, err = stream.Write(append(portData, '\n'))
	if err != nil {
		log.Printf("Failed to send port list: %v", err)
		return
	}
	fmt.Println("Sent port list to client:", clientPorts)
	stream.Close()

	// Handle new streams
	go func() {
		for {
			clientStream, err := conn.AcceptStream(context.Background())
			if err != nil {
				log.Printf("Failed to accept QUIC stream: %v", err)
				return
			}
			go relayToUpstream(clientStream)
		}
	}()
}

// ** Relays QUIC data to the predefined TCP upstream **
func relayToUpstream(stream quic.Stream) {
	streamID := int(stream.StreamID()) // Get QUIC stream ID

	// Ensure we have a known mapping
	if streamID >= len(upstreamPorts) {
		log.Printf("Stream %d has no predefined upstream mapping!", streamID)
		return
	}

	upstreamPort := upstreamPorts[streamID]
	upstreamAddr := fmt.Sprintf("localhost:%d", upstreamPort)

	// Connect to upstream TCP server
	upstreamConn, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		log.Printf("Failed to connect to upstream %s: %v", upstreamAddr, err)
		return
	}
	defer upstreamConn.Close()

	fmt.Printf("[Server] Stream %d relaying to TCP upstream %s\n", streamID, upstreamAddr)

	// Relay QUIC → TCP
	go io.Copy(upstreamConn, stream)

	// Relay TCP → QUIC
	io.Copy(stream, upstreamConn)
}

// ** Client: QUIC Client that listens on TCP and sends over QUIC **
func client() {
	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second, // Ensures QUIC connection remains open
	}

	conn, err := quic.DialAddr(context.Background(), "localhost:4242", generateTLSConfig(), quicConfig)
	if err != nil {
		log.Fatalf("Failed to connect to QUIC server: %v", err)
	}
	fmt.Println("Client connected to QUIC server...")

	// Receive port list from the server
	initialStream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Fatalf("Failed to accept initial QUIC stream: %v", err)
	}

	reader := bufio.NewReader(initialStream)
	portData, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read port list: %v", err)
	}
	initialStream.Close()

	var ports []int
	if err := json.Unmarshal([]byte(portData), &ports); err != nil {
		log.Fatalf("Failed to parse port list: %v", err)
	}
	fmt.Println("Client received port list:", ports)

	// Start TCP listeners
	for _, port := range ports {
		go listenOnTCP(conn, port)
	}

	select {} // Keep running
}

// ** Listens on a TCP port and forwards traffic over QUIC **
func listenOnTCP(conn quic.Connection, port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to listen on TCP port %d: %v", port, err)
	}
	fmt.Printf("Client listening on TCP port %d\n", port)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept TCP connection on port %d: %v", port, err)
			continue
		}

		go forwardToQUIC(conn, tcpConn, port)
	}
}

// ** Forwards TCP data to a QUIC stream **
func forwardToQUIC(conn quic.Connection, tcpConn net.Conn, port int) {
	defer tcpConn.Close()

	stream, err := conn.OpenStream()
	if err != nil {
		log.Printf("Failed to open QUIC stream for port %d: %v", port, err)
		return
	}
	defer stream.Close()

	fmt.Printf("[Client] Stream %d forwarding TCP port %d over QUIC\n", stream.StreamID(), port)

	// Relay TCP → QUIC
	go io.Copy(stream, tcpConn)

	// Relay QUIC → TCP
	io.Copy(tcpConn, stream)
}

var certPEMBase64 = `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ1VENDQVYrZ0F3SUJBZ0lVVm9kaDdSbStFY2t5TGg0WTFIWFgwOHhMeGxVd0NnWUlLb1pJemowRUF3SXcKRWpFUU1BNEdBMVVFQXd3SFVWVkpReTFEUVRBZUZ3MHlOVEF4TWpReU1EVXdNakphRncwek5UQXhNakl5TURVdwpNakphTUJZeEZEQVNCZ05WQkFNTUMzRjFhV010WTJ4cFpXNTBNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBECkFRY0RRZ0FFTTRhWlBjWjV0WUNJY24zTldaU3NBYmFnVUkyTzV2R0hxaTNZWFg0RGgrTE16NGJ2WEFzOVl1ckoKR0wreHVqUWUvcGUwd212cGVqWlptbVlRWjdpdlRLT0JqakNCaXpBTUJnTlZIUk1CQWY4RUFqQUFNQllHQTFVZApFUVFQTUEyQ0MzRjFhV010WTJ4cFpXNTBNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyCkJnRUZCUWNEQWpBZEJnTlZIUTRFRmdRVXgvVEFRZWwrZGNpOVFhUWhVNk9lY0d5Z1E5Y3dId1lEVlIwakJCZ3cKRm9BVXlCS3F1MWMxQ2F1UENIM0NyNStRWVgrNnk0b3dDZ1lJS29aSXpqMEVBd0lEU0FBd1JRSWdPNXAyUmZCVQpQdGNkZTQ2UEp5WU9zbjRUS3hWWEZMeUp2Ym9VaVJtTUpPNENJUUNaWTN1QWNWSTFkTmpFMkxodGZHVEdaMXQ4Cmx3K3BiUGR6UXUzUzZ6NjlnQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K` // Replace with your encoded certificate
var keyPEMBase64 = `LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3hNUnBuZVVvOThJVzkvSkQKUTc0d1JJSjdBcmV1YThPZlBZZFhFM0NPc2J1aFJBTkNBQVF6aHBrOXhubTFnSWh5ZmMxWmxLd0J0cUJRalk3bQo4WWVxTGRoZGZnT0g0c3pQaHU5Y0N6MWk2c2tZdjdHNk5CNytsN1RDYStsNk5sbWFaaEJudUs5TQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              // Replace with your encoded private key
var CAPEMBase64 = `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpRENDQVMrZ0F3SUJBZ0lVQVV4bkplMmxNK1pkeFM0Um01MnNML0lCdGZNd0NnWUlLb1pJemowRUF3SXcKRWpFUU1BNEdBMVVFQXd3SFVWVkpReTFEUVRBZUZ3MHlOVEF4TWpReU1EUTVOVE5hRncwek5UQXhNakl5TURRNQpOVE5hTUJJeEVEQU9CZ05WQkFNTUIxRlZTVU10UTBFd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DCkFBUVRNUDErZEEzRGtIcUZvV0VGUlA5SkszWlZhQ0paMitTMkFuN01rOVlRdHc5ZGYvblZsQnhZQ3c3UXNvZTYKVmJYQkRNZk80V3ZaaXpwYStXdmFPZ3g5bzJNd1lUQWRCZ05WSFE0RUZnUVV5QktxdTFjMUNhdVBDSDNDcjUrUQpZWCs2eTRvd0h3WURWUjBqQkJnd0ZvQVV5QktxdTFjMUNhdVBDSDNDcjUrUVlYKzZ5NG93RHdZRFZSMFRBUUgvCkJBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNBUVl3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnYjBTUWdWWVQKSjJQamthT1QzdnRIMGs0NFVObUxkVnJybW9hNzhtb2UwNXdDSUFkcC9Qanl2Z0lDS3VFZS9DaUJQZnFJZ1ZHbwptZCtKZnlLeFBYVVdGRWJSCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K`

// Decode Base64 cert and key, then load into TLS config
func generateTLSConfig() *tls.Config {
	certPEM, err := base64.StdEncoding.DecodeString(certPEMBase64)
	if err != nil {
		fmt.Printf("Failed to decode cert: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyPEMBase64)
	if err != nil {
		fmt.Printf("Failed to decode key: %v", err)
	}

	caPEM, err := base64.StdEncoding.DecodeString(CAPEMBase64)
	if err != nil {
		fmt.Printf("Failed to decode ca cert: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		fmt.Printf("Failed to append CA certificate")
	}

	// Load server certificate and key
	certs, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fmt.Printf("Failed to load X509 key pair: %v", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{certs},
		RootCAs:            caPool, // Trust server signed by CA
		NextProtos:         []string{"quic-tunnel"},
		InsecureSkipVerify: true, // Don't skip verification (mTLS required)
	}

}
