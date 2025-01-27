package messaging

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

func SendStream(u QuicMessage, stream quic.Stream) error {
	jsonBytes, err := u.Marshal()
	if err != nil {
		panic(err)
	}

	padding := []byte{0x00, 0x00}
	finalBytes := append(padding, jsonBytes...)
	finalBytes = append(finalBytes, padding...)

	_, err = stream.Write(finalBytes)
	if err != nil {
		log.Fatalf("Error writing to QUIC stream: %v", err)
	}
	return nil
}

// readJSON reads and parses a Message struct from a QUIC stream
func ReadJSON(stream quic.Stream, apikey string) (QuicMessage, error) {
	// Read data from QUIC stream
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return QuicMessage{}, fmt.Errorf("failed to read from QUIC stream: %w", err)
	}

	// Ensure there is enough data for proper slicing
	if n < 4 { // At least 2 bytes padding + JSON + 2 bytes padding
		return QuicMessage{}, fmt.Errorf("received data too short")
	}

	// Slice out the padding (assuming it's always 2 bytes before and after)
	data := buf[2 : n-2] // Remove first 2 and last 2 bytes

	fmt.Printf("Raw JSON Data After Trimming: %s\n", string(data))

	var msg QuicMessage

	err = msg.UnMarshal(data) // ✅ Correct call
	if err != nil {
		fmt.Printf("Failed to parse JSON: %v\n", err)
		return msg, fmt.Errorf("received data too short")
	}

	// err = json.Unmarshal(data, &msg)
	// if err != nil {
	// 	return QuicMessage{}, fmt.Errorf("failed to parse JSON: %w", err)
	// }
	fmt.Printf("Got Data: %+v\n", msg)

	if !CheckApiKey(msg.ApiKey, apikey) {
		fmt.Printf("Closing Stream, API key mismatch. StreamInfo: %v\n", msg)
		stream.Close()
	}
	// d := msg.Marshal()
	fmt.Printf("Accepted Stream. StreamInfo: %+v\n", msg)

	return msg, nil
}

func HandleStream(ctx context.Context, conn quic.Connection, i int, host QuicMessage, rhost string) {
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping stream handler.")
			return
		default:
			// Open a new stream
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				if ctx.Err() != nil {
					fmt.Println("Connection shutting down.")
					return
				}
				log.Printf("Error opening stream: %v", err)
				time.Sleep(2 * time.Second) // Backoff before retrying
				continue
			}

			// Prepare message
			n := QuicMessage{
				ApiKey:     host.ApiKey,
				RemoteHost: host.RemoteHost,
				Protocol:   host.Protocol,
				ClientHost: rhost,
				StreamID:   stream.StreamID(),
			}
			fmt.Printf("Values: %+v\n", n)

			upstreams, err := n.Marshal()
			if err != nil {
				log.Printf("Error marshalling upstream data: %v", err)
				stream.Close()
				return
			}

			fmt.Printf("Upstreams: %s\n", string(upstreams)) // ✅ Print only after confirming success

			// Send data (pass `n`, not `*n`)
			err = SendStream(n, stream)
			if err != nil {
				log.Printf("Error sending stream: %v", err)
			}
			// Read response
			response := make([]byte, 1024)
			nBytes, err := stream.Read(response)
			if err != nil {
				log.Printf("Error reading response: %v", err)
				stream.Close()
				return
			}

			fmt.Printf("Received response: %s\n", string(response[:nBytes]))

		}
	}
}
