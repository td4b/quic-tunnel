package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"quic-tunnel/logger"
	"quic-tunnel/tcp"
	"quic-tunnel/tlsconf"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

var (
	logd = logger.Loger
)

func StartServer(listenaddr string) {

	// Create TUN interface tun1 (server-side interface)
	iface1, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		logd.Fatal("Failed to create TUN device: %v", err)
	}
	logd.Info("TUN interface created: %s", iface1.Name())

	// Configure TUN interface with IP
	configureTun1(iface1.Name(), "10.10.10.10/30")

	conf := &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
		MaxIdleTimeout:  60 * time.Minute,
	}

	// Start QUIC Server
	listener, err := quic.ListenAddr(
		listenaddr,
		tlsconf.GenerateTLSConfig(certPEMBase64, keyPEMBase64, CAPEMBase64),
		conf)
	if err != nil {
		logd.Fatal("Failed to start QUIC listener: %v", err)
	}

	logd.Info("Listening for QUIC connections on %s", listenaddr)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("QUIC accept error: %v", err)
			continue
		}
		logd.Info("Opened session from client. Starting Handlers.")
		go handleClient(session, iface1)
	}
}

func handleClient(session quic.Connection, iface1 *water.Interface) {
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Failed to accept QUIC stream: %v", err)
		return
	}
	defer stream.Close()

	// Use buffered channels to queue packets
	packetQueue := make(chan []byte, 100)

	// Start packet reader and writer goroutines
	go readFromTunAndQueue(iface1, packetQueue)
	go sendQueuedPacketsOverQUIC(packetQueue, stream)

	// Read from QUIC and inject into TUN
	readFromQUICToTun(stream, iface1)
}

// Reads from TUN and adds to queue
func readFromTunAndQueue(iface1 *water.Interface, queue chan<- []byte) {
	buffer := make([]byte, 1500)
	debug := os.Getenv("DEBUG")

	for {
		n, err := iface1.Read(buffer)
		if err != nil {
			log.Printf("TUN read error: %v", err)
			continue
		}

		if n > len(buffer) {
			log.Printf("Error: Read size %d exceeds buffer length %d\n", n, len(buffer))
			continue
		}

		// Copy packet data and send to queue
		packet := make([]byte, n)
		copy(packet, buffer[:n])

		if debug == "true" {
			tcp.Readtcp(packet)
		}

		queue <- packet
	}
}

// Sends packets over QUIC from queue
func sendQueuedPacketsOverQUIC(queue <-chan []byte, stream quic.Stream) {
	for packet := range queue {
		_, err := stream.Write(packet)
		if err != nil {
			log.Printf("QUIC write error: %v", err)
			return
		}
	}
}

// Reads from QUIC and injects into TUN
func readFromQUICToTun(stream quic.Stream, iface1 *water.Interface) {
	buffer := make([]byte, 1500)
	debug := os.Getenv("DEBUG")

	for {
		n, err := stream.Read(buffer)
		if err != nil {
			log.Printf("QUIC read error: %v", err)
			return
		}

		if n > len(buffer) {
			log.Printf("Error: Read size %d exceeds buffer length %d\n", n, len(buffer))
			continue
		}

		if debug == "true" {
			tcp.Readtcp(buffer[:n])
		}

		_, err = iface1.Write(buffer[:n])
		if err != nil {
			log.Printf("TUN write error: %v", err)
			return
		}
	}
}

// Configure the TUN interface on the server
func configureTun1(iface, ip string) {
	cmd := fmt.Sprintf("ip addr add %s dev %s peer 10.10.10.9 && ip link set %s up", ip, iface, iface)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		log.Fatalf("Failed to configure TUN: %v", err)
	}

	// Add a default route via TUN interface
	// cmd = fmt.Sprintf("ip route add default via 10.10.10.9 dev tun0")
	// err = exec.Command("sh", "-c", cmd).Run()
	// if err != nil {
	// 	log.Fatalf("Failed to configure TUN: %v", err)
	// }
}

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
