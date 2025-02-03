package tcp

import (
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
)

func Readtcp(buffer []byte) {
	// Extract IPv4 header
	versionAndIHL := buffer[0]
	version := versionAndIHL >> 4
	ihl := (versionAndIHL & 0x0F) * 4 // Header Length in bytes

	if version != 4 {
		log.Println("Not an IPv4 packet")
	}

	totalLength := binary.BigEndian.Uint16(buffer[2:4])
	protocol := buffer[9]
	srcIP := net.IP(buffer[12:16])
	dstIP := net.IP(buffer[16:20])

	// Ensure it's a TCP packet
	if protocol != 6 {
		log.Println("Not a TCP packet")
	}

	// Extract TCP header
	tcpStart := ihl
	srcPort := binary.BigEndian.Uint16(buffer[tcpStart : tcpStart+2])
	dstPort := binary.BigEndian.Uint16(buffer[tcpStart+2 : tcpStart+4])
	seqNum := binary.BigEndian.Uint32(buffer[tcpStart+4 : tcpStart+8])
	ackNum := binary.BigEndian.Uint32(buffer[tcpStart+8 : tcpStart+12])
	dataOffset := (buffer[tcpStart+12] >> 4) * 4
	flags := buffer[tcpStart+13] & 0x3F // Extract only flag bits

	// Decode TCP flags
	flagMap := map[string]bool{
		"URG": flags&0x20 != 0,
		"ACK": flags&0x10 != 0,
		"PSH": flags&0x08 != 0,
		"RST": flags&0x04 != 0,
		"SYN": flags&0x02 != 0,
		"FIN": flags&0x01 != 0,
	}

	// Extract TCP payload
	tcpPayload := buffer[tcpStart+dataOffset : totalLength]

	// Print extracted TCP frame information
	log.Printf("\n========== TCP Packet ==========")
	log.Printf("IPv4 Src: %s -> Dst: %s", srcIP, dstIP)
	log.Printf("TCP Src Port: %d -> Dst Port: %d", srcPort, dstPort)
	log.Printf("Sequence Number: %d", seqNum)
	log.Printf("Acknowledgment Number: %d", ackNum)
	log.Printf("Flags: %+v", flagMap)
	log.Printf("Payload (Hex):\n%s", hex.Dump(tcpPayload))
}
