package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"quic-tunnel/logger"
	"quic-tunnel/models"
	"time"

	"github.com/quic-go/quic-go"
)

// Client configuration
var (
	serverAddr string
	localAddr  string
	logd       = logger.Loger
)

func Startclient(serverAddr string) {

	listeneraddr := "172.21.71.94"

	// Establish QUIC session
	session, err := quic.DialAddr(context.Background(), serverAddr, generateTLSConfig(), nil)
	if err != nil {
		log.Printf("❌ Failed to connect to QUIC server: %v", err)
	}

	// ✅ Open a QUIC stream immediately and start keep-alives.
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		logd.Info("❌ Failed to open QUIC stream: %s", err)
		session.CloseWithError(0, "stream error")
	}
	go startKeepAlive(stream)

	clients, err := GetClients(stream)
	if err != nil {
		panic(err)
	}

	for _, cl := range clients {
		// handle clients async.
		go CreateClientConn(stream, listeneraddr, cl)
	}

	// need to implement blocking
	time.Sleep(3600 * time.Second)

}

func CreateClientConn(stream quic.Stream, listeneraddr string, cl models.Upstream) {
	logd.Info("🔹 Handling client: %+v", cl)
	localAddr := net.JoinHostPort(listeneraddr, cl.Port)

	// ✅ Handle TCP Connections
	if cl.Protocol == "tcp" {
		listener, err := net.Listen("tcp", localAddr)
		logd.Info("✅ Starting Local TCP listener: %s", localAddr)
		if err != nil {
			logd.Fatal("❌ Failed to start local TCP listener: %v", err)
		}
		defer listener.Close()

		log.Printf("✅ Client TCP listener ready on %s, forwarding to QUIC server", localAddr)

		// Accept incoming TCP connections
		tcpConn, err := listener.Accept()
		if err != nil {
			logd.Info("❌ Failed to accept local TCP connection: %s", err)
			return
		}

		logd.Info("🔗 New TCP connection received, forwarding to QUIC server")
		go handleTunnelTCP(cl, tcpConn, stream)
	}

	// Implement UDP later.
	// if cl.Protocol == "udp" {
	// 	logd.Info("Starting Local UDP listener: %s", localAddr)

	// 	// Create UDP listener
	// 	udpConn, err := net.ListenPacket("udp", localAddr)
	// 	if err != nil {
	// 		logd.Fatal("❌ Failed to start local UDP listener: %v", err)
	// 	}
	// 	defer udpConn.Close()

	// 	logd.Info("✅ Client UDP listener ready on %s, forwarding to QUIC server", localAddr)

	// 	// Start bidirectional UDP <-> QUIC relay
	// 	go relayUDPToQUIC(udpConn, stream)
	// 	go relayQUICToUDP(udpConn, stream)
	// }
}

// GetClients sends a request to the QUIC server and reads the list of upstreams.
func GetClients(stream quic.Stream) ([]models.Upstream, error) {
	request := "quic-clients\n"

	// Send the request
	_, err := stream.Write([]byte(request))
	if err != nil {
		logd.Info("❌ QUIC request failed, closing connection: %v", err)
		return nil, err
	}
	logd.Info("📤 Requested Clients port list from Server")

	// Read response from the server
	var response []byte
	buf := make([]byte, 1024)

	for {
		n, err := stream.Read(buf)
		if err != nil {
			logd.Info("❌ Failed to read QUIC response: %v", err)
			return nil, err
		}

		response = append(response, buf[:n]...)

		// Ensure we received the full message
		if buf[n-1] == '\n' {
			break
		}
	}

	logd.Info("🔹 Received raw data: %s", string(response))

	// Remove "quic-clients: " prefix before parsing JSON
	trimmedResponse := string(response)
	if len(trimmedResponse) > 14 && trimmedResponse[:14] == "quic-clients: " {
		trimmedResponse = trimmedResponse[14:]
	}

	// Parse JSON into `models.Addresses`
	var addresses models.Addresses
	err = json.Unmarshal([]byte(trimmedResponse), &addresses)
	if err != nil {
		logd.Info("❌ Failed to parse JSON response: %v", err)
		return nil, err
	}

	logd.Info("✅ Parsed Upstream List: %+v", addresses.Upstream)
	return addresses.Upstream, nil
}

// **Start a Keep-Alive Ping Routine to Keep QUIC Connection Active**
func startKeepAlive(stream quic.Stream) {
	ticker := time.NewTicker(10 * time.Second) // Send keep-alive every 15s
	defer ticker.Stop()

	for range ticker.C {
		_, err := stream.Write([]byte("quic-ping\n")) // Send a small heartbeat
		if err != nil {
			logd.Info("❌ QUIC Keep-Alive failed, closing connection: %s", err)
			return
		}
		logd.Info("💓 Sent QUIC Keep-Alive Ping to Server") // ✅ Fixed message
	}
}

func handleTunnelTCP(clientid models.Upstream, tcpConn net.Conn, quicStream quic.Stream) {
	defer tcpConn.Close()

	logd.Info("🚀 Starting TCP <-> QUIC relay for %s:%s (%s)", clientid.Address, clientid.Port, clientid.Protocol)

	// ✅ **TCP → QUIC Relay**
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := tcpConn.Read(buf)
			if err != nil {
				logd.Info("❌ TCP Read error, closing: %s", err)
				return
			}

			// ✅ **Marshal client info into JSON**
			clientinfo, err := json.Marshal(clientid)
			if err != nil {
				logd.Fatal("❌ JSON Marshal error: %v", err)
				return
			}

			// ✅ **Define 4-byte padding**
			padding := []byte{0x00, 0x00, 0x00, 0x00}

			// ✅ **Construct final QUIC message: [Metadata] + [Padding] + [TCP Data]**
			finalBuf := append(clientinfo, padding...) // Append JSON metadata + padding
			finalBuf = append(finalBuf, buf[:n]...)    // Append TCP data

			// ✅ **Log and send message over QUIC**
			logd.Info("📤 TCP → QUIC: Metadata=%s | TCP Data=%s", string(clientinfo), string(buf[:n]))
			_, err = quicStream.Write(finalBuf)
			if err != nil {
				logd.Info("❌ QUIC Write error, closing: %s", err)
				return
			}
		}
	}()

	// ✅ **QUIC → TCP Relay**
	buf := make([]byte, 1024)
	for {
		n, err := quicStream.Read(buf)
		if err != nil {
			logd.Info("❌ QUIC Read error, closing: %s", err)
			return
		}

		// ✅ **Ensure Keep-Alive Messages Are Ignored**
		message := string(buf[:n])
		if message == "quic-ping\n" {
			logd.Info("💓 Ignoring Keep-Alive Ping from QUIC")
			continue
		}

		// ✅ **Log and forward to TCP**
		logd.Info("📥 QUIC → TCP: %s", message)
		_, err = tcpConn.Write(buf[:n])
		if err != nil {
			logd.Info("❌ TCP Write error, closing: %s", err)
			return
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
		logd.Fatal("Failed to decode cert: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyPEMBase64)
	if err != nil {
		logd.Fatal("Failed to decode key: %v", err)
	}

	caPEM, err := base64.StdEncoding.DecodeString(CAPEMBase64)
	if err != nil {
		logd.Fatal("Failed to decode ca cert: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatal("Failed to append CA certificate")
	}

	// Load server certificate and key
	certs, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		logd.Fatal("Failed to load X509 key pair: %v", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{certs},
		RootCAs:            caPool, // Trust server signed by CA
		NextProtos:         []string{"quic-tunnel"},
		InsecureSkipVerify: false, // Don't skip verification (mTLS required)
	}

}
