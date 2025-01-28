package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"quic-tunnel/messaging"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	API_KEY = "supersecretapikey"
	iface   = make(map[string]net.Conn)
)

// var clientPorts = map[string]int{
// 	"port1": 8081,
// 	"port2": 8082,
// } // Client listens here

var conf = messaging.ParseClientConfigs(API_KEY, "localhost:8084/tcp,localhost:8085/tcp")

// ** QUIC Server: Accepts Client Connections and Relays to Upstream TCP **
func Server(ctx context.Context, wg *sync.WaitGroup) {

	// sets the API key variable globally.
	os.Setenv("API_KEY", API_KEY)

	defer wg.Done()
	quicConfig := &quic.Config{
		MaxIdleTimeout:  45 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
	}

	listener, err := quic.ListenAddr("localhost:4241", generateTLSConfig(), quicConfig)
	if err != nil {
		log.Fatalf("Failed to start QUIC server: %v", err)
	}
	fmt.Println("Server listening on port 4242...")

	go func() {
		<-ctx.Done()
		fmt.Println("Shutting down server...")
		listener.Close()
	}()

	// the problem here is with the TCP upstream handler, it needs to be moved outside the
	// context of the stream and quic handlers.
	// we take care of this by mapping *net.Conn to remotehost
	// based on this mapping we then have streamID and remotehost.
	// we use remote host as the common value to map between the two.

	wg.Add(len(conf))

	for _, host := range conf {

		tcpReady := make(chan struct{})
		go func(host messaging.QuicMessage) {
			tcpConn := messaging.MonitorTCPHealth(ctx, host)
			if tcpConn == nil {
				close(tcpReady)
				return
			}
			iface[host.RemoteHost] = tcpConn
			defer tcpConn.Close()
			close(tcpReady)
		}(host)

		go func(host messaging.QuicMessage) {
			<-tcpReady
			defer wg.Done()
			messaging.QuicListenerHandler(ctx, *listener, host)
		}(host)
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
