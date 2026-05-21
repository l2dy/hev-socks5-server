// dns-udp-test resolves a DNS domain via SOCKS5 UDP ASSOCIATE.
//
// Usage:
//
//	go run . [-proxy 127.0.0.1:1080] [-dns 8.8.8.8:53] [-domain example.com]
//
// The program opens a UDP ASSOCIATE session through the SOCKS5 proxy, sends a
// standard DNS A-record query to the chosen DNS server, then prints the
// resolved addresses returned in the answer section.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/txthinking/socks5"
)

func main() {
	proxy := flag.String("proxy", "127.0.0.1:1080", "SOCKS5 proxy address (host:port)")
	dnsServer := flag.String("dns", "8.8.8.8:53", "DNS server to query through the proxy (host:port)")
	domain := flag.String("domain", "example.com", "Domain name to resolve")
	flag.Parse()

	client, err := socks5.NewClient(*proxy, "", "", 10, 10)
	if err != nil {
		log.Fatalf("create socks5 client: %v", err)
	}

	// Open a UDP connection through the proxy targeting the DNS server.
	conn, err := client.Dial("udp", *dnsServer)
	if err != nil {
		log.Fatalf("socks5 UDP dial: %v", err)
	}
	defer conn.Close()

	txID := uint16(rand.N(0xffff) + 1)

	// Build a DNS query for the A record of the requested domain.
	msg := buildQuery(txID, *domain)

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write(msg); err != nil {
		log.Fatalf("send DNS query: %v", err)
	}

	// A DNS UDP response is at most 512 bytes in the classic limit, but
	// modern resolvers may use EDNS0 for larger replies; 4096 is safe.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("read DNS response: %v", err)
	}

	addrs, err := parseResponse(buf[:n], txID)
	if err != nil {
		log.Fatalf("parse DNS response: %v", err)
	}

	if len(addrs) == 0 {
		fmt.Printf("%s: no A records found\n", *domain)
		return
	}
	for _, a := range addrs {
		fmt.Printf("%s -> %s\n", *domain, a)
	}
}

// buildQuery constructs a DNS wire-format A-record query for name.
//
// Wire format (RFC 1035 §4):
//
//	Header  (12 bytes)
//	Question section
func buildQuery(txID uint16, name string) []byte {
	var buf bytes.Buffer

	// Header: ID, FLAGS (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	binary.Write(&buf, binary.BigEndian, txID)
	binary.Write(&buf, binary.BigEndian, uint16(0x0100)) // QR=0, Opcode=0, RD=1
	binary.Write(&buf, binary.BigEndian, uint16(1))      // QDCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // ANCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // NSCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // ARCOUNT

	// QNAME: each label prefixed with its length, terminated by 0x00
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00) // root label

	binary.Write(&buf, binary.BigEndian, uint16(1)) // QTYPE  A
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS IN

	return buf.Bytes()
}

// dnsHeader mirrors the 12-byte DNS message header.
type dnsHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// parseResponse parses a DNS wire-format response and returns all A-record IPs.
func parseResponse(data []byte, txID uint16) ([]net.IP, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short (%d bytes)", len(data))
	}

	var hdr dnsHeader
	binary.Read(bytes.NewReader(data[:12]), binary.BigEndian, &hdr)

	if hdr.ID != txID {
		return nil, fmt.Errorf("transaction ID mismatch: got 0x%04x, want 0x%04x", hdr.ID, txID)
	}
	rcode := hdr.Flags & 0x000f
	if rcode != 0 {
		return nil, fmt.Errorf("DNS RCODE %d", rcode)
	}

	// Walk past the question section.
	offset := 12
	for i := 0; i < int(hdr.QDCount); i++ {
		offset, _ = skipName(data, offset)
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answer RRs.
	var addrs []net.IP
	for i := 0; i < int(hdr.ANCount); i++ {
		offset, _ = skipName(data, offset)
		if offset+10 > len(data) {
			break
		}
		rrtype := binary.BigEndian.Uint16(data[offset:])
		offset += 2 // TYPE
		offset += 2 // CLASS
		offset += 4 // TTL
		rdlen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2

		if rrtype == 1 && rdlen == 4 && offset+4 <= len(data) { // A record
			addrs = append(addrs, net.IP(data[offset:offset+4]).To16())
		}
		offset += rdlen
	}
	return addrs, nil
}

// skipName advances offset past a DNS name (handling pointer compression).
func skipName(data []byte, offset int) (int, error) {
	for offset < len(data) {
		n := int(data[offset])
		if n == 0 {
			return offset + 1, nil
		}
		if n&0xc0 == 0xc0 { // pointer
			return offset + 2, nil
		}
		offset += 1 + n
	}
	return offset, fmt.Errorf("malformed DNS name")
}
