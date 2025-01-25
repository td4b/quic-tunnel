package models

import "github.com/quic-go/quic-go"

type Upstream struct {
	Address  string `json:"address"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type Addresses struct {
	Info     string `json:"info"`
	Upstream []Upstream
}

type ClientConn struct {
	Stream  quic.Stream
	Session quic.Connection
}
