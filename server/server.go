package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"quic-tunnel/logger"
	"quic-tunnel/models"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Server configuration
var (
	logd                = logger.Loger
	upstreamConnections = make(map[string]*net.TCPConn) // Persistent TCP connections
	mu                  sync.Mutex                      // Protects upstreamConnections map
	ClientConn          *models.ClientConn
	Addresses           *models.Addresses
	Upstreams           *[]models.Upstream
)

// Startserver starts the QUIC tunnel server with multiple upstreams.
func Startserver(address, port string, upstreams []models.Upstream) {

	quicAddr := address + ":" + port

	// configure the global pointers
	Addresses = &models.Addresses{
		Upstream: upstreams,
	}
	Upstreams = &upstreams

	// Perform an initial health check for all upstreams
	if !healthCheckAll(upstreams) {
		logd.Fatal("❌ Health check failed! Unable to connect to one or more upstreams")
	}

	logd.Info("✅ Initial health check successful! Forwarding traffic to upstreams.")

	// Start periodic health check
	go func() {
		for {
			time.Sleep(30 * time.Second)
			if !healthCheckAll(upstreams) {
				logd.Fatal("❌ An UpStream is UnHealthy! Lost connection to one or more upstreams!")
			}
		}
	}()

	// Start QUIC listener
	listener, err := quic.ListenAddr(quicAddr, generateTLSConfig(), nil)
	if err != nil {
		logd.Fatal("❌ QUIC Listen failed: %v", err)
	}
	logd.Info("🚀 QUIC Server listening on %s", quicAddr)

	// Create the quic session.
	session, err := listener.Accept(context.Background())
	if err != nil {
		logd.Info("❌ Failed to accept QUIC session: %v", err)
	}

	logd.Info("🔗 New QUIC session established from: %s", session.RemoteAddr().String())

	// Start the initial handshake stream
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		logd.Fatal("❌ Failed to accept QUIC stream: %s", err)
		return
	}
	logd.Info("🎉 New QUIC stream accepted!")

	ClientConn = &models.ClientConn{
		Stream:  stream,
		Session: session,
	}

	// Reads the initial handshake message.
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		logd.Fatal("❌ QUIC Read error.")
		return
	}

	message := string(buf[:n])
	if message == "quic-clients\n" {
		_, err = handleclients()
		if err != nil {
			panic(err)
		}
		UpStreamDatagrams()
	}

}

func handleclients() (bool, error) {
	// wrap in goroutine with sleep to wait for keepalives so session doesn't die.
	logd.Info("✅ Received Clients list request.")

	// Marshal JSON response
	js, err := json.Marshal(Addresses)
	if err != nil {
		logd.Fatal("❌ Failed to marshal JSON: %v", err)
		return false, err
	}

	// Append a newline to signal the end of the message
	response := append([]byte("quic-clients: "), js...)
	response = append(response, '\n')

	// Write response
	_, err = ClientConn.Stream.Write(response)
	if err != nil {
		logd.Fatal("❌ QUIC Write error: %v", err)
		return false, err
	}

	logd.Info("📤 Sent client list response: %s", string(response))
	return true, nil
}

// Base64-encoded certificate and key (output from `base64 -w 0`)
var certPEMBase64 = `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ5akNDQVhDZ0F3SUJBZ0lVVm9kaDdSbStFY2t5TGg0WTFIWFgwOHhMeGxRd0NnWUlLb1pJemowRUF3SXcKRWpFUU1BNEdBMVVFQXd3SFVWVkpReTFEUVRBZUZ3MHlOVEF4TWpReU1EVXdNRFphRncwek5UQXhNakl5TURVdwpNRFphTUJZeEZEQVNCZ05WQkFNTUMzRjFhV010YzJWeWRtVnlNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBECkFRY0RRZ0FFdEtWU3NnNkJ0QWRXMThOdVZicWdXS2dldEdYc1BBZXZSUzlNL3hHMTdacEtWRHF4ZFQzN3FqdWQKUDZidE56cWZ4YVR2QzA2OXg3QTdGWllmcU02OXNhT0JuekNCbkRBTUJnTlZIUk1CQWY4RUFqQUFNQ2NHQTFVZApFUVFnTUI2Q0MzRjFhV010YzJWeWRtVnlnZ2xzYjJOaGJHaHZjM1NIQkg4QUFBRXdEZ1lEVlIwUEFRSC9CQVFECkFnV2dNQk1HQTFVZEpRUU1NQW9HQ0NzR0FRVUZCd01CTUIwR0ExVWREZ1FXQkJTaSs0Tk43cG41TzlndUZncE8Kc1k3ZHRpb3JrakFmQmdOVkhTTUVHREFXZ0JUSUVxcTdWelVKcTQ4SWZjS3ZuNUJoZjdyTGlqQUtCZ2dxaGtqTwpQUVFEQWdOSUFEQkZBaUVBbG9xdWVwQ2V0bFVnS1pHTVJDK3ZoV01LNWhtUnU3WGtCQ1A3NGJKeFhrVUNJRHZ0CjVQakZ4VVd5UXRlQ2k3YnIvN3h2YUMxSmZtNGFaYnc5K3BUKzJ2Q2sKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=` // Replace with your encoded certificate
var keyPEMBase64 = `LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3J0aW1SdHdZRC9MR2w5RHQKdHUzdjR6NVJHN1k3M1FEY2tISVRlT1Z2dDZpaFJBTkNBQVMwcFZLeURvRzBCMWJYdzI1VnVxQllxQjYwWmV3OApCNjlGTDB6L0ViWHRta3BVT3JGMVBmdXFPNTAvcHUwM09wL0ZwTzhMVHIzSHNEc1ZsaCtvenIyeAotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          // Replace with your encoded private key
var CAPEMBase64 = `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpRENDQVMrZ0F3SUJBZ0lVQVV4bkplMmxNK1pkeFM0Um01MnNML0lCdGZNd0NnWUlLb1pJemowRUF3SXcKRWpFUU1BNEdBMVVFQXd3SFVWVkpReTFEUVRBZUZ3MHlOVEF4TWpReU1EUTVOVE5hRncwek5UQXhNakl5TURRNQpOVE5hTUJJeEVEQU9CZ05WQkFNTUIxRlZTVU10UTBFd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DCkFBUVRNUDErZEEzRGtIcUZvV0VGUlA5SkszWlZhQ0paMitTMkFuN01rOVlRdHc5ZGYvblZsQnhZQ3c3UXNvZTYKVmJYQkRNZk80V3ZaaXpwYStXdmFPZ3g5bzJNd1lUQWRCZ05WSFE0RUZnUVV5QktxdTFjMUNhdVBDSDNDcjUrUQpZWCs2eTRvd0h3WURWUjBqQkJnd0ZvQVV5QktxdTFjMUNhdVBDSDNDcjUrUVlYKzZ5NG93RHdZRFZSMFRBUUgvCkJBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNBUVl3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnYjBTUWdWWVQKSjJQamthT1QzdnRIMGs0NFVObUxkVnJybW9hNzhtb2UwNXdDSUFkcC9Qanl2Z0lDS3VFZS9DaUJQZnFJZ1ZHbwptZCtKZnlLeFBYVVdGRWJSCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K`

// Decode Base64 cert and key, then load into TLS config
func generateTLSConfig() *tls.Config {
	certPEM, err := base64.StdEncoding.DecodeString(certPEMBase64)
	if err != nil {
		logd.Fatal("Failed to decode cert: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyPEMBase64)
	if err != nil {
		logd.Fatal("Failed to decode key: %v", err)
	}

	caPEM, err := base64.StdEncoding.DecodeString(CAPEMBase64)
	if err != nil {
		logd.Fatal("Failed to decode key: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		logd.Fatal("Failed to append CA certificate")
	}

	// Load server certificate and key
	certs, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		logd.Fatal("Failed to load X509 key pair: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certs},
		ClientCAs:    caPool,                         // Trust client certs signed by CA
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
		NextProtos:   []string{"quic-tunnel"},
	}
}
