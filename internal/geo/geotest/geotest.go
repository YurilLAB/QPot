// Package geotest writes a small GeoIP database for tests.
package geotest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The network the test database knows, and what it records for it.
const (
	KnownIP = "81.2.69.160" // inside 81.0.0.0/8
	Country = "SE"
	City    = "Stockholm"
	ASN     = "1257"
)

// mmdbString encodes a UTF-8 string (data type 2) of under 29 bytes.
func mmdbString(s string) []byte { return append([]byte{2<<5 | byte(len(s))}, s...) }

// mmdbMap encodes a map (type 7) of under 29 entries from key, value pairs.
func mmdbMap(kv ...[]byte) []byte {
	out := []byte{7<<5 | byte(len(kv)/2)}
	for _, b := range kv {
		out = append(out, b...)
	}
	return out
}

// mmdbUint encodes an unsigned integer of the given type (5: uint16, 6:
// uint32) in as few bytes as it needs.
func mmdbUint(typ byte, v uint64) []byte {
	var b []byte
	for ; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{typ<<5 | byte(len(b))}, b...)
}

// WriteMMDB writes a MaxMind-format database, in the published binary
// format, that knows one IPv4 network, 81.0.0.0/8, as a Stockholm address in
// AS 1257, and returns its path.
func WriteMMDB(t testing.TB) string {
	t.Helper()
	const nodes, first = 8, 81 // a /8: one tree node per bit of the first byte
	record := func(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }
	var tree []byte
	for i := 0; i < nodes; i++ {
		bit := (first >> (7 - i)) & 1
		next := i + 1
		if i == nodes-1 {
			next = nodes + 16 // the first record of the data section
		}
		left, right := record(nodes), record(nodes) // nodes: not found
		if bit == 0 {
			left = record(next)
		} else {
			right = record(next)
		}
		tree = append(append(tree, left...), right...)
	}
	data := mmdbMap(
		mmdbString("country"), mmdbMap(mmdbString("iso_code"), mmdbString(Country)),
		mmdbString("city"), mmdbMap(mmdbString("names"), mmdbMap(mmdbString("en"), mmdbString(City))),
		mmdbString("autonomous_system_number"), mmdbUint(6, 1257),
	)
	meta := mmdbMap(
		mmdbString("binary_format_major_version"), mmdbUint(5, 2),
		mmdbString("binary_format_minor_version"), mmdbUint(5, 0),
		mmdbString("database_type"), mmdbString("QPot-Test"),
		mmdbString("ip_version"), mmdbUint(5, 4),
		mmdbString("node_count"), mmdbUint(6, nodes),
		mmdbString("record_size"), mmdbUint(5, 24),
	)
	var file bytes.Buffer
	file.Write(tree)
	file.Write(make([]byte, 16)) // the data section separator
	file.Write(data)
	file.WriteString("\xab\xcd\xefMaxMind.com")
	file.Write(meta)
	path := filepath.Join(t.TempDir(), "test.mmdb")
	if err := os.WriteFile(path, file.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
