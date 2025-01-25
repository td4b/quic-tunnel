package server

import (
	"bytes"
	"encoding/json"
	"net"
	"quic-tunnel/models"
	"time"
)

func UpStreamDatagrams() {

	for {

		// Read and Write Buffers for the Stream
		writebuf := make([]byte, 4096)
		readbuf := make([]byte, 4096)

		n, err := ClientConn.Stream.Read(writebuf)
		if err != nil {
			logd.Info("❌ QUIC Read error: %v", err)
			return
		}

		// **Check if it's a Keep-Alive Ping**
		message := string(writebuf[:n])
		if message == "quic-ping\n" {
			logd.Info("💓 Received Heartbeat from client: %s", ClientConn.Session.RemoteAddr().String())
		} else {
			// **Ensure Proper Message Format (Metadata + Padding + TCP Data)**
			padIndex := bytes.Index(writebuf[:n], []byte{0x00, 0x00, 0x00, 0x00})
			if padIndex == -1 {
				logd.Info("❌ Invalid message format: Padding not found")
			}

			// Extract JSON Metadata
			jsonData := writebuf[:padIndex]

			// Extract TCP Data (after the padding)
			tcpData := writebuf[padIndex+4 : n]

			// Parse JSON Metadata
			var clientInfo map[string]string
			err = json.Unmarshal(jsonData, &clientInfo)
			if err != nil {
				logd.Info("❌ Failed to parse JSON: %v", err)
			}

			logd.Info("✅ Parsed JSON Metadata: %+v", clientInfo)

			// Find the correct upstream based on the client info
			upstream, found := findUpstream(clientInfo)
			if !found {
				logd.Info("❌ No matching upstream found for client: %+v", clientInfo)
			}

			logd.Info("🔄 Forwarding to Upstream: %s:%s (%s)", upstream.Address, upstream.Port, upstream.Protocol)

			// Establish TCP connection to the upstream
			tcpConn := getUpstreamConnection(upstream)
			if tcpConn == nil {
				logd.Info("❌ Failed to connect to upstream: %s:%s", upstream.Address, upstream.Port)
			}

			// Send the initial TCP data
			_, err = tcpConn.Write(tcpData)
			if err != nil {
				logd.Info("❌ Error writing TCP data to upstream: %v", err)
			}
			// Gets the response and relays it downstream to the client
			_, err = tcpConn.Read(readbuf)
			if err != nil {
				logd.Info("❌ Error reading TCP data to upstream: %v", err)
			}

			// ✅ **Marshal client info into JSON**
			clientinfo, err := json.Marshal(upstream)
			if err != nil {
				logd.Fatal("❌ JSON Marshal error: %v", err)
				return
			}

			// ✅ **Define 4-byte padding**
			padding := []byte{0x00, 0x00, 0x00, 0x00}

			// ✅ **Construct final QUIC message: [Metadata] + [Padding] + [TCP Data]**
			finalBuf := append(clientinfo, padding...)  // Append JSON metadata + padding
			finalBuf = append(finalBuf, readbuf[:n]...) // Append TCP data

			// Write back to the stream
			_, err = ClientConn.Stream.Write(finalBuf)
			if err != nil {
				logd.Info("❌ QUIC Write error: %v", err)
				return
			}

		}

	}

}

// Finds the correct upstream based on client request
func findUpstream(clientInfo map[string]string) (models.Upstream, bool) {
	for _, upstream := range Addresses.Upstream {
		if upstream.Address == clientInfo["address"] && upstream.Port == clientInfo["port"] {
			logd.Info("✅ Match found: %s:%s (%s)", upstream.Address, upstream.Port, upstream.Protocol)
			return upstream, true
		}
	}
	return models.Upstream{}, false
}

// Maintains persistent TCP connections for upstreams
func getUpstreamConnection(upstream models.Upstream) *net.TCPConn {
	addr := net.JoinHostPort(upstream.Address, upstream.Port)

	mu.Lock()
	defer mu.Unlock()

	// If connection already exists, return it
	if conn, exists := upstreamConnections[addr]; exists {
		return conn
	}

	// Establish new TCP connection
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		logd.Info("❌ Connection failed to %s: %v", addr, err)
		return nil
	}

	tcpConn := conn.(*net.TCPConn)
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)
	upstreamConnections[addr] = tcpConn

	logd.Info("✅ New TCP connection established: %s", addr)
	return tcpConn
}
