package server

import (
	"net"
	"quic-tunnel/models"
	"time"
)

// healthCheckAll checks the connectivity for all upstreams
func healthCheckAll(upstreams []models.Upstream) bool {
	allHealthy := true
	for _, upstream := range upstreams {
		if !healthCheck(upstream) {
			logd.Info("⚠️ Health check failed for %s:%s/%s", upstream.Address, upstream.Port, upstream.Protocol)
			allHealthy = false
		}
	}
	return allHealthy
}

// healthCheck checks the connectivity of a single upstream (TCP or UDP)
func healthCheck(upstream models.Upstream) bool {
	tcpConn := getUpstreamConnection(upstream)
	if tcpConn == nil {
		return false
	}

	// Enable TCP keep-alive
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)

	// **Check if the connection is still alive using a non-blocking read**
	tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second)) // 1 sec timeout
	buf := make([]byte, 1)
	_, err := tcpConn.Read(buf)

	// **Fix: Handle all error types correctly**
	if err != nil {
		// **Check if the error is a timeout (connection alive but no data)**
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout means connection is alive, just no data
			logd.Info("⚠️ No data from %s, but connection is still alive.", upstream.Address)
			return true
		}

		// **All other errors indicate a broken connection**
		logd.Info("❌ Connection to %s is dead, reconnecting... Error: %v", upstream.Address, err)
		delete(upstreamConnections, net.JoinHostPort(upstream.Address, upstream.Port))
		return false
	}

	logd.Info("✅ Health Check Success: %s", upstream.Address)
	return true
}
