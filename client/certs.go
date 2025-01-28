package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
)

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
