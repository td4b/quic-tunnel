package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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

type Listeners struct {
	Listener *net.Listener
	Port     string
	Host     string
	Stream   quic.Stream
}

var (
	listenerMap = make(map[string]*Listeners)
	hostmap     = make(map[string]*Listeners)
)

func client() {

	// session1, session2
	ports := []string{"8081", "8082"}

	// Establish QUIC session
	session, err := quic.DialAddr(context.Background(), "localhost:3142", generateTLSConfig(), nil)
	if err != nil {
		log.Printf("❌ Failed to connect to QUIC server: %v", err)
	}
	for _, port := range ports {
		// establish TCP listeners.

		go func() {
			listener, err := net.Listen("tcp", "localhost:"+port)

			fmt.Printf("✅ Starting Local TCP listener: %s\n", "localhost:"+port)
			if err != nil {
				fmt.Printf("❌ Failed to start local TCP listener: %v", err)
			}

			stream, err := session.OpenStreamSync(context.Background())
			if err != nil {
				fmt.Printf("❌ Failed to open QUIC stream: %s", err)
				session.CloseWithError(0, "stream error")
			}

			listenerMap[port] = &Listeners{
				Listener: &listener,
				Port:     port,
				Stream:   stream,
			}
		}()

	}

	for {
		for listener, _ := range listenerMap {
			stream := listenerMap[listener].Stream
			go HandleStream(stream)
		}
	}

}

func HandleStream(stream quic.Stream) {

	message := fmt.Sprintf("Hello from %v", stream.StreamID())
	_, err := stream.Write([]byte(message))
	if err != nil {
		fmt.Println("Error writing to stream:", err)
	}
	buf := make([]byte, 1024)
	_, err = stream.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Got Data %s from streamID: %v\n", string(buf), stream.StreamID())

}

func server() {

	hosts := []string{"localhost:8084", "localhost:8085"}

	// Start QUIC listener
	listener, err := quic.ListenAddr("localhost:3142", generateTLSConfig(), nil)
	if err != nil {
		fmt.Printf("❌ QUIC Listen failed: %v", err)
	}
	fmt.Printf("🚀 QUIC Server listening on %s\n", "localhost:3142")

	session, err := listener.Accept(context.Background())
	if err != nil {
		panic(err)
	}

	// Create upstreams
	for _, host := range hosts {
		// establish TCP listeners.
		listener, err := net.Listen("tcp", host)

		fmt.Printf("✅ Starting Local TCP listener: %s\n", host)
		if err != nil {
			fmt.Printf("❌ Failed to start local TCP listener: %v", err)
		}

		stream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			fmt.Printf("❌ Failed to open QUIC stream: %s", err)
			session.CloseWithError(0, "stream error")
		}

		hostmap[host] = &Listeners{
			Listener: &listener,
			Host:     host,
			Stream:   stream,
		}

	}

	for {
		for listener, _ := range listenerMap {
			stream := listenerMap[listener].Stream
			go HandleStream(stream)
		}
	}

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
