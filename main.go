package main

// (c) 2017 Daniel Hauenstein, SlimSec IT Gmbh

// TODO:
// - Check for Encryption actually used after Client Handshake (next packets of server..)
// - Check for certification authenification (mutual client-server connection authenticated)

import (
	"flag"
	"fmt"
)

// Config comprises all configs for a test
type Config struct {
	Src       string
	Dst       string
	SrcPort   int
	DstPort   int
	Filter    string
	Type      string
	Interface string
	Count     int
}

// Cipher is a known cipher
type Cipher struct {
	Code     string
	Name     string
	Protocol string
	KX       string
	AU       string
	Enc      string
	Bits     string
	MAC      string
}

var dstHost *string = flag.String("dst", "", "Destination Host for Tests")
var dstPort *int = flag.Int("dport", 443, "Destination Port for Tests")
var srcHost *string = flag.String("src", "", "Source Host for Tests (optional)")
var srcPort *int = flag.Int("sport", 0, "Source Port for Tests (optional, 0 to disable)")
var debug *bool = flag.Bool("debug", false, "Enable verbose debugging output")

// This should be one of:
// - client
// - server
// - connection (not implemented yet, tests if an existing conection is encrypted)
var scanType *string = flag.String("scantype", "client", "What type of connection to test (client, server - default: client)")

var iface *string = flag.String("iface", "eth0", "Interface to listen for packets")
var reportFilename *string = flag.String("output", "report.json", "File to store results in, will overwrite existing files!")

var count *int = flag.Int("count", 0, "Number of valid packets to collect before stopping (report will be written")

// Debug is just a very simple debug function to output data depending on the debug commandline flag
func Debug(format, msg string) {
	if *debug == false {
		return
	}
	fmt.Printf(format, msg)
}
func main() {
	flag.Parse()
	filter := "tcp"
	if *dstHost != "" {
		filter += fmt.Sprintf(" and dst host %s", *dstHost)
	}
	if *dstPort != 0 {
		filter += fmt.Sprintf(" and dst port %d", *dstPort)
	}
	if *srcHost != "" {
		filter += fmt.Sprintf(" and src host %s", *srcHost)
	}
	if *srcPort != 0 {
		filter += fmt.Sprintf(" and src port %d", *srcPort)
	}
	config := Config{
		Src:       *srcHost,
		Dst:       *dstHost,
		SrcPort:   *srcPort,
		DstPort:   *dstPort,
		Filter:    filter,
		Type:      *scanType,
		Interface: *iface,
		Count:     *count,
	}
	switch *scanType {
	case "client":
		ClientTest(config)
	case "server":
		ServerTest(config)

	}
}
