package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

const (
	tunName    = "tun0"
	listenAddr = "0.0.0.0:4242"
)

func main() {
	// Create TUN interface
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}
	fmt.Println("TUN interface created:", iface.Name())

	// Configure IP for the TUN interface (Linux example)
	configureTun(iface.Name(), "10.0.0.1/24")

	// Start QUIC listener
	listener, err := quic.ListenAddr(listenAddr, generateTLSConfig(), nil)
	if err != nil {
		log.Fatalf("Failed to start QUIC listener: %v", err)
	}
	fmt.Println("Listening for QUIC connections on", listenAddr)

	for {
		session, err := listener.Accept(nil)
		if err != nil {
			log.Printf("QUIC accept error: %v", err)
			continue
		}

		go handleClient(session, iface)
	}
}

func handleClient(session quic.Connection, iface *water.Interface) {
	stream, err := session.AcceptStream(nil)
	if err != nil {
		log.Printf("Failed to accept QUIC stream: %v", err)
		return
	}
	defer stream.Close()

	buffer := make([]byte, 1500)
	for {
		n, err := stream.Read(buffer)
		if err != nil {
			log.Printf("Stream read error: %v", err)
			return
		}
		// Write packet to TUN interface
		_, err = iface.Write(buffer[:n])
		if err != nil {
			log.Printf("TUN write error: %v", err)
			return
		}
	}
}

func configureTun(iface, ip string) {
	cmd := fmt.Sprintf("ip addr add %s dev %s && ip link set %s up", ip, iface, iface)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		log.Fatalf("Failed to configure TUN: %v", err)
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
