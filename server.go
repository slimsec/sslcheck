package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

type CheckedCipher struct {
	Cipher    Cipher
	Handshake string
	Supported bool
}

// Result is the struct of a server test result
type ServerResult struct {
	Config         Config
	CheckedCiphers []CheckedCipher
}

// Handshake is a SSL/TLS Handshake
type Handshake struct {
	Name    string
	Payload []byte
}

var handshakes = []Handshake{
	Handshake{"TLS v1.3", []byte("\x80\x2c\x01\x03\x04\x00\x03\x00\x00\x00\x20")},
	Handshake{"TLS v1.2", []byte("\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20")},
	Handshake{"TLS v1.1", []byte("\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20")},
	Handshake{"TLS v1.0", []byte("\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20")},
	Handshake{"SSL v3.0", []byte("\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20")},
	Handshake{"SSL v2.0", []byte("\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20")},
}

var challenge = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

// ServerTest tests for server encryption
func ServerTest(config Config) {
	fd, err := os.Create(*reportFilename)
	if err != nil {
		panic("Can not open result file")
	}
	var serverResult ServerResult
	serverResult.Config = config
	for _, handshake := range handshakes {
		fmt.Printf("Testing Handshake variant %s\n", handshake.Name)
		for _, cipher := range Ciphers {
			fmt.Printf("\tTesting Cipher %40s  - ", cipher.Name)
			r := checkCipher(cipher, handshake, config)
			if r {
				fmt.Printf("OK\n")
			} else {
				fmt.Printf("NOK\n")
			}
			serverResult.CheckedCiphers = append(serverResult.CheckedCiphers, CheckedCipher{
				Cipher:    cipher,
				Handshake: handshake.Name,
				Supported: r,
			})
		}
	}
	writeReportAndExit(fd, serverResult)
}

// This one is more or less a 1:1 copy of sslmap (http://www.thesprawl.org/projects/sslmap/)
func checkCipher(c Cipher, h Handshake, config Config) bool {
	connString := fmt.Sprintf("%s:%d", config.Dst, config.DstPort)
	conn, err := net.Dial("tcp", connString)
	if err != nil {
		log.Fatalf("Could not connect to host %s on port %d. Exiting!\n", config.Dst, config.DstPort)
	}
	// Let's wait for 10 seconds to receive a reply from the server - otherwise fail this test
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.Close()
	cipherPayload, _ := hex.DecodeString(c.Code[2:len(c.Code)])
	payload := h.Payload
	payload = append(payload, cipherPayload...)
	payload = append(payload, challenge...)
	_, err = conn.Write(payload)
	if err != nil {
		return false
	}
	var buf bytes.Buffer
	written, err := io.CopyN(&buf, conn, 13)
	if err != nil || written == 0 {
		return false
	}

	state := false
	res := buf.Bytes()
	if res[0] == '\x16' { // Server Hello, 0x15 is Alert Code
		state = true
	} else {
		if written < 13 {
			return false
		}
		if bytes.Compare(res[10:13], []byte("\x00\x03")) == 0 {
			state = true
		} else {
			state = false
		}
	}

	return state
}
