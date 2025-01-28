package messaging

import (
	"encoding/json"
	"strings"

	"github.com/quic-go/quic-go"
)

// Message represents the JSON message to be sent
type QuicMessage struct {
	ApiKey     string        `json:"apiKey"` // Base64-encoded seed value
	RemoteHost string        `json:"remoteHost"`
	Protocol   string        `json:"protocol"`
	ClientHost string        `json:"clientHost"`
	StreamID   quic.StreamID `json:"streamid"`
	Data       []byte        `json:"data"`
}

type ClientConfig struct {
	UpStream QuicMessage `json:"upstream"`
}

func (u QuicMessage) Marshal() ([]byte, error) {
	if u.ApiKey == "" {
		return []byte("null"), nil
	}
	type metadataCopy QuicMessage
	return json.Marshal(metadataCopy(u))
}

func (u *QuicMessage) UnMarshal(data []byte) error {
	return json.Unmarshal(data, u) // ✅ Directly unmarshal into `u`
}

func ParseClientConfigs(apikey string, input string) []QuicMessage {
	entries := strings.Split(input, ",")
	var configs []QuicMessage

	for _, entry := range entries {
		parts := strings.Split(entry, "/")
		if len(parts) != 2 {
			panic("invalid /tcp protocol format")
		}

		hostPort := parts[0]
		protocol := parts[1]

		hostParts := strings.Split(hostPort, ":")
		if len(hostParts) != 2 {
			panic("invalid host:port format")
		}

		host := hostParts[0]
		port := hostParts[1]
		remotehost := host + ":" + port
		config := QuicMessage{
			ApiKey:     apikey,
			RemoteHost: remotehost,
			Protocol:   protocol,
			ClientHost: remotehost,
		}
		configs = append(configs, config)
	}

	return configs
}
