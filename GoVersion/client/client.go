package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

const (
	serverAddr = "127.0.0.1:4222" // Replace with actual QUIC server IP
)

func main() {
	// Create TUN interface tun0
	iface0, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}
	fmt.Println("TUN interface created:", iface0.Name())

	//configureTun0(iface0.Name(), "10.10.10.9/30")

	conf := &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
		MaxIdleTimeout:  60 * time.Minute,
	}

	// Connect to QUIC Server
	session, err := quic.DialAddr(context.Background(), serverAddr, generateTLSConfig(), conf)
	if err != nil {
		log.Fatalf("Failed to connect to QUIC server: %v", err)
	}
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("Failed to open QUIC stream: %v", err)
	}

	//buffer := make([]byte, 1500)
	buffer := []byte("Do you See me?")
	stream.Write(buffer)

	fmt.Println("sent stream!")

	// buffer := make([]byte, 1500)

	// go func() {
	// 	// Read responses from QUIC and inject them back into tun0
	// 	for {
	// 		n, err := stream.Read(buffer)
	// 		if err != nil {
	// 			log.Printf("Stream read error: %v", err)
	// 			return
	// 		}

	// 		tcp.Readtcp(buffer[:n])

	// 		_, err = iface0.Write(buffer[:n])
	// 		if err != nil {
	// 			log.Printf("TUN write error: %v", err)
	// 			return
	// 		}
	// 	}
	// }()

	// // Read packets from tun0 and send them via QUIC
	// for {
	// 	n, err := iface0.Read(buffer)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	tcp.Readtcp(buffer[:n])

	// 	// Send packet via QUIC
	// 	_, err = stream.Write(buffer[:n])
	// 	if err != nil {
	// 		log.Printf("QUIC write error: %v", err)
	// 		return
	// 	}
	// }
}

// func configureTun0(iface, ip string) {
// 	// Assign IP address to the TUN interface
// 	cmd := fmt.Sprintf("ip addr add %s dev %s && ip link set %s up", ip, iface, iface)
// 	err := exec.Command("sh", "-c", cmd).Run()
// 	if err != nil {
// 		log.Fatalf("Failed to configure TUN: %v", err)
// 	}

// 	// Add a default route via TUN interface
// 	cmd = fmt.Sprintf("ip route add default via 10.10.10.9 dev tun0")
// 	err = exec.Command("sh", "-c", cmd).Run()
// 	if err != nil {
// 		log.Fatalf("Failed to configure TUN: %v", err)
// 	}
// }

var certPEMBase64 = `
	LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJlVENDQVN1Z0F3SUJBZ0lVUVgvWVBSOGh1
	QXB6aDhMVXRoV1Nvb3pTZ2lZd0JRWURLMlZ3TUJJeEVEQU8KQmdOVkJBTU1CMUZWU1VNdFEwRXdI
	aGNOTWpVd01USTJNRGN3T0RNeFdoY05NelV3TVRJME1EY3dPRE14V2pBVwpNUlF3RWdZRFZRUURE
	QXR4ZFdsakxXTnNhV1Z1ZERBcU1BVUdBeXRsY0FNaEFOS09DSmYzeTdTQythZW9yRkxCClNCdDJq
	VXVGUGlOeU5OcVFBNXRTUnQ4TW80R09NSUdMTUF3R0ExVWRFd0VCL3dRQ01BQXdGZ1lEVlIwUkJB
	OHcKRFlJTGNYVnBZeTFqYkdsbGJuUXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CTUdBMVVkSlFRTU1B
	b0dDQ3NHQVFVRgpCd01DTUIwR0ExVWREZ1FXQkJScjJUTHAvU1RMSzI0WTByeXZyRm1MTmZhdmNU
	QWZCZ05WSFNNRUdEQVdnQlNTCi9YMmhyMEZDcFZNNCtISjFFdGt0cFFBeFFUQUZCZ01yWlhBRFFR
	Q3lja1F5cURNdlczQkNNek4xRWxrNm1qVGkKOHFkSlVtSUp2QkxrTnA4VS9NOXlKYmhQN09EMllG
	S3IvS3prd3piaENtZnhMbGhFTjc0aVpYcVRIWFlQCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
	`

var keyPEMBase64 = `
	LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUVWLzJJcXFk
	aFoxWFp5Rit2bGFjSjhjMVZoN25aelQzUFI4anloZDAzR0EKLS0tLS1FTkQgUFJJVkFURSBLRVkt
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
		InsecureSkipVerify: true, // Don't skip verification (mTLS required)
	}

}

// func main() {

// 	// Create TUN interface tun0
// 	iface0, err := water.New(water.Config{DeviceType: water.TUN})
// 	if err != nil {
// 		log.Fatalf("Failed to create TUN device: %v", err)
// 	}
// 	fmt.Println("TUN interface created:", iface0.Name())

// 	// Create TUN interface tun1
// 	iface1, err := water.New(water.Config{DeviceType: water.TUN})
// 	if err != nil {
// 		log.Fatalf("Failed to create TUN device: %v", err)
// 	}
// 	fmt.Println("TUN interface created:", iface1.Name())

// 	// Configure IP for the TUN interface
// 	configureTun0(iface0.Name(), "10.10.10.9/30")
// 	configureTun1(iface1.Name(), "10.10.10.10/30")

// 	buffer := make([]byte, 1500)

// 	for {
// 		n, err := iface0.Read(buffer)
// 		if err != nil {
// 			log.Fatal(err)
// 		}

// 		// Parse the received frame as an IPv4 packet
// 		if n < 20 {
// 			log.Println("Packet too small for IPv4")
// 			continue
// 		}

// 		tcp.Readtcp(buffer)

// 		iface1.Write(buffer)

// 	}
// }

// // Configure the TUN interface
// func configureTun0(iface, ip string) {
// 	cmd := fmt.Sprintf("ip addr add %s dev %s && ip link set %s up", ip, iface, iface)
// 	err := exec.Command("sh", "-c", cmd).Run()
// 	if err != nil {
// 		log.Fatalf("Failed to configure TUN: %v", err)
// 	}
// }
