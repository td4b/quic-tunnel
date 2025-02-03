package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
)

func stripNewlines(base64s string) string {

	cleanBase64 := strings.ReplaceAll(base64s, "\t", "")
	cleanBase64 = strings.TrimSpace(cleanBase64)
	return cleanBase64
}

// Decode Base64 cert and key, then load into TLS config
func GenerateTLSConfig(cert string, key string, ca string) *tls.Config {

	certPEM, err := base64.StdEncoding.DecodeString(stripNewlines(cert))
	if err != nil {
		log.Fatalf("Failed to decode Base64 certificate: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(stripNewlines(key))
	if err != nil {
		fmt.Printf("Failed to decode key: %v", err)
	}

	caPEM, err := base64.StdEncoding.DecodeString(stripNewlines(ca))
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
