package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"quic-tunnel/messaging"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	tlsconf = generateTLSConfig()
	cert    = tlsconf.Certificates[0]
	API_KEY = "supersecretapikey"
)

// var clientPorts = map[string]int{
// 	"port1": 8081,
// 	"port2": 8082,
// } // Client listens here

// ** QUIC Server: Accepts Client Connections and Relays to Upstream TCP **
func Server(ctx context.Context, wg *sync.WaitGroup) {

	defer wg.Done()
	quicConfig := &quic.Config{
		MaxIdleTimeout:  45 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
	}

	listener, err := quic.ListenAddr("localhost:4242", generateTLSConfig(), quicConfig)
	if err != nil {
		log.Fatalf("Failed to start QUIC server: %v", err)
	}
	fmt.Println("Server listening on port 4242...")

	go func() {
		<-ctx.Done()
		fmt.Println("Shutting down server...")
		listener.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Server stopped accepting new connections.")
			return
		default:
			conn, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					fmt.Println("Server shutting down gracefully.")
					return
				}
				log.Printf("Error accepting connection: %v", err)
				continue
			}

			go handleConnection(ctx, conn)
		}
	}

}

func handleConnection(ctx context.Context, conn quic.Connection) {
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping connection handler.")
			return
		default:
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				if ctx.Err() != nil {
					fmt.Println("Connection shutting down.")
					return
				}
				log.Printf("Error accepting stream: %v", err)
				continue
			}

			go handleStream(ctx, stream)
		}
	}
}

func handleStream(ctx context.Context, stream quic.Stream) {
	select {
	case <-ctx.Done():
		fmt.Println("Stopping stream processing.")
		return
	default:
		_, err := messaging.ReadJSON(stream, API_KEY)
		if err != nil {
			log.Printf("Error reading JSON: %v", err)
		}
	}
}

var certPEMBase64 = `
	LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpakNDQVR5Z0F3SUJBZ0lVUVgvWVBSOGh1
	QXB6aDhMVXRoV1Nvb3pTZ2lVd0JRWURLMlZ3TUJJeEVEQU8KQmdOVkJBTU1CMUZWU1VNdFEwRXdI
	aGNOTWpVd01USTJNRGN3T0RJeFdoY05NelV3TVRJME1EY3dPREl4V2pBVwpNUlF3RWdZRFZRUURE
	QXR4ZFdsakxYTmxjblpsY2pBcU1BVUdBeXRsY0FNaEFLRUQ1VWJIaXBPbUYvQmJ1N1RGCjVWWjY0
	Wk5lRUtLMWdHUEdsaGxWcER5Nm80R2ZNSUdjTUF3R0ExVWRFd0VCL3dRQ01BQXdKd1lEVlIwUkJD
	QXcKSG9JTGNYVnBZeTF6WlhKMlpYS0NDV3h2WTJGc2FHOXpkSWNFZndBQUFUQU9CZ05WSFE4QkFm
	OEVCQU1DQjRBdwpFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd0V3SFFZRFZSME9CQllFRkdUWXhG
	R0JzSTVQMjk3aERoMDl4V2g3CnhIVmZNQjhHQTFVZEl3UVlNQmFBRkpMOWZhR3ZRVUtsVXpqNGNu
	VVMyUzJsQURGQk1BVUdBeXRsY0FOQkFMWEIKYUxZQnlrYXFvN1N3bG1UbTQza0gxN2NLSTZqUVFP
	VW41THpkREVRanJjcmxpT0xGR1hnelhrMTVaUjhWbCsrYwpqYW5odndqL0VDVTV3bEVLTXdjPQot
	LS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
	`

var keyPEMBase64 = `
	LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSURPekUvVk9M
	bkxYelpheVNDL1Z0OVlnb2MydG0ydlZ3YXNBUGozcU9VT2gKLS0tLS1FTkQgUFJJVkFURSBLRVkt
	LS0tLQo=
	`

var CAPEMBase64 = `
	LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJTRENCKzZBREFnRUNBaFJmak94dmNiV0pX
	S2NObDZZbE9NYjR5bTZKU2pBRkJnTXJaWEF3RWpFUU1BNEcKQTFVRUF3d0hVVlZKUXkxRFFUQWVG
	dzB5TlRBeE1qWXdOekE0TURsYUZ3MHpOVEF4TWpRd056QTRNRGxhTUJJeApFREFPQmdOVkJBTU1C
	MUZWU1VNdFEwRXdLakFGQmdNclpYQURJUUNjK1ZYSkY3eHVua3plTlRZL0JhSVV0TkQxCmFuTHBN
	cFh2MUQ0UThPMXFWNk5qTUdFd0hRWURWUjBPQkJZRUZKTDlmYUd2UVVLbFV6ajRjblVTMlMybEFE
	RkIKTUI4R0ExVWRJd1FZTUJhQUZKTDlmYUd2UVVLbFV6ajRjblVTMlMybEFERkJNQThHQTFVZEV3
	RUIvd1FGTUFNQgpBZjh3RGdZRFZSMFBBUUgvQkFRREFnRUdNQVVHQXl0bGNBTkJBSko5SllQcW9B
	bndyL2JEd1QwbkN2Nk9GZWRUCm5seXhIV3h1OEZQK015UzlpeXhlUDFiWHFpdk15blNGd0ltb3ln
	SG1velRUdlF4QkxvM0xGbzNNZWdjPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
	`

func stripNewlines(base64s string) string {

	cleanBase64 := strings.ReplaceAll(base64s, "\t", "")
	cleanBase64 = strings.TrimSpace(cleanBase64)
	return cleanBase64
}

// Decode Base64 cert and key, then load into TLS config
func generateTLSConfig() *tls.Config {

	certPEM, err := base64.StdEncoding.DecodeString(stripNewlines(certPEMBase64))
	if err != nil {
		log.Fatalf("Failed to decode Base64 certificate: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(stripNewlines(keyPEMBase64))
	if err != nil {
		fmt.Printf("Failed to decode key: %v", err)
	}

	caPEM, err := base64.StdEncoding.DecodeString(stripNewlines(CAPEMBase64))
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
		InsecureSkipVerify: false, // Don't skip verification (mTLS required)
	}

}
