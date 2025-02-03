package client

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"quic-tunnel/logger"
	"quic-tunnel/tcp"
	"quic-tunnel/tlsconf"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

var (
	logd = logger.Loger
)

// StartClient initializes the QUIC client and handles networking
func StartClient(sendaddr string) {
	// Create TUN interface tun0
	iface0, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		logd.Fatal("Failed to create TUN device: %v", err)
	}
	logd.Info("TUN interface created: %s", iface0.Name())

	configureTun0(iface0.Name(), "10.10.10.9/30")

	conf := &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
		MaxIdleTimeout:  60 * time.Minute,
	}

	// Connect to QUIC Server
	session, err := quic.DialAddr(
		context.Background(),
		sendaddr, tlsconf.GenerateTLSConfig(certPEMBase64, keyPEMBase64, CAPEMBase64),
		conf)
	if err != nil {
		log.Fatalf("Failed to connect to QUIC server: %v", err)
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("Failed to open QUIC stream: %v", err)
	}
	logd.Info("Opened Stream to Server. Starting Stream handlers.")

	// Packet queue for batching TUN reads
	packetQueue := make(chan []byte, 100)

	// Start the optimized goroutines
	go readFromTunAndQueue(iface0, packetQueue)
	go sendQueuedPacketsOverQUIC(packetQueue, stream)
	go readFromQUICToTun(stream, iface0)

	// Block forever
	select {}
}

// Reads from TUN and queues packets
func readFromTunAndQueue(iface0 *water.Interface, queue chan<- []byte) {
	buffer := make([]byte, 1500)

	debug := os.Getenv("DEBUG")

	for {
		n, err := iface0.Read(buffer)
		if err != nil {
			log.Printf("TUN read error: %v", err)
			continue
		}

		if n > len(buffer) {
			log.Printf("Error: Read size %d exceeds buffer length %d\n", n, len(buffer))
			continue
		}

		// Copy the packet data before sending to queue
		packet := make([]byte, n)
		copy(packet, buffer[:n])

		if debug == "true" {
			tcp.Readtcp(packet)
		}

		queue <- packet
	}
}

// Sends packets over QUIC from the queue
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
func readFromQUICToTun(stream quic.Stream, iface0 *water.Interface) {
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

		_, err = iface0.Write(buffer[:n])
		if err != nil {
			log.Printf("TUN write error: %v", err)
			return
		}
	}
}

// Configure the TUN interface on the client
func configureTun0(iface, ip string) {
	cmd := fmt.Sprintf("ip addr add %s peer 10.10.10.10 dev %s && ip link set %s up", ip, iface, iface)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		log.Fatalf("Failed to configure TUN: %v", err)
	}

	// Add a default route via TUN interface
	cmd = fmt.Sprintf("ip route add default via 10.10.10.10 dev tun0")
	err = exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		log.Fatalf("Failed to configure TUN: %v", err)
	}
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
