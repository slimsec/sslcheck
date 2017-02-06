package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Connection is the handshake of one TLS Connection
type Connection struct {
	SrcHost        string
	SrcPort        int
	DstHost        string
	DstPort        int
	ConnectionType string
	Ciphers        []Cipher
}

// Result is the struct of a client test result
type Result struct {
	Config           Config
	ClientHandshakes []Connection
}

// ClientTest test for client encryption
func ClientTest(config Config) {
	var result Result
	count := 0

	if handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(config.Filter); err != nil { // optional
		panic(err)
	} else {
		fd, err := os.Create(*reportFilename)
		if err != nil {
			panic("Can not open result file")
		}
		result.Config = config
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		fmt.Println("Start inspecting packets\nPress Ctrl-C to stop process and save report.")

		go func() {
			for packet := range packetSource.Packets() {
				connection, err := handlePacket(packet) // Do something with a packet here.
				if err != nil {
					Debug("Error with parsing packet: %s\n", err.Error())
				} else {
					result.ClientHandshakes = append(result.ClientHandshakes, connection)
					count++
					if config.Count == count {
						fmt.Printf("Finished collecting %d packets. Writing report and exiting.\n", config.Count)
						writeReportAndExit(fd, result)
					}
				}
			}
		}()
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		for _ = range c {
			fmt.Println("Got SIGINT, writing report and exiting..")
			writeReportAndExit(fd, result)
		}
	}
}
func writeReportAndExit(fd *os.File, result interface{}) {
	json, err := json.Marshal(result)
	if err != nil {
		fmt.Println("ERROR: Can not parse results")
		os.Exit(1)
	}
	fd.Write(json)
	fmt.Printf("Written %d bytes to '%s'. Exiting..\n", len(json), *reportFilename)
	os.Exit(0)

}
func handlePacket(packet gopacket.Packet) (Connection, error) {
	//fmt.Printf("%+v\n", packet)
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer != nil {
		tcp := packet.TransportLayer().(*layers.TCP)
		if tcp == nil {
			return Connection{}, fmt.Errorf("Not an Application Layer..")
		}
		payload := tcp.Payload
		var connection Connection
		if len(payload) > 16 {
			iplayer := packet.NetworkLayer().(*layers.IPv4)
			connection.SrcHost = iplayer.SrcIP.String()
			connection.DstHost = iplayer.DstIP.String()
			connection.SrcPort = int(tcp.SrcPort)
			connection.DstPort = int(tcp.DstPort)
			//hostname := iplayer.
			// var ciphers []Cipher
			if bytes.Compare(payload[2:5], []byte{0x01, 0x00, 0x02}) == 0 {
				ciphercount := int(payload[5]) * 256
				ciphercount += int(payload[6])
				fmt.Printf("Got SSLv2 Handshake (%+v ciphers) from %s to %s..\n", ciphercount/3, iplayer.SrcIP, iplayer.DstIP)
				connection.ConnectionType = "SSLv2"
				connection.Ciphers = getCiphers(payload[11:11+ciphercount], 3)

			} else if bytes.Compare(payload[0:5], []byte{0x80, 0x80, 0x01, 0x03, 0x01}) == 0 {
				// SSLv2 Wrapped TLS Handshake
				ciphercount := int(payload[5]) * 256
				ciphercount += int(payload[6])
				fmt.Printf("Got SSLv2 Wrapped Handshake (%+v ciphers) from %s to %s..\n", ciphercount/3, iplayer.SrcIP, iplayer.DstIP)
				connection.ConnectionType = "SSLv2 wrapped TLS"
				connection.Ciphers = getCiphers(payload[11:11+ciphercount], 3)
			} else if bytes.Compare(payload[0:3], []byte{0x16, 0x03, 0x00}) == 0 {
				ciphercount := int(payload[44]) * 256
				ciphercount += int(payload[45])
				fmt.Printf("Got SSLv3 Handshake (%d ciphers) from %s to %s..\n", ciphercount/2, iplayer.SrcIP, iplayer.DstIP)
				connection.ConnectionType = "SSLv3/TLSv1.0"
				connection.Ciphers = getCiphers(payload[46:46+ciphercount], 2)
			} else if bytes.Compare(payload[0:3], []byte{0x16, 0x03, 0x01}) == 0 && payload[5] == 0x01 {
				ciphercount := int(payload[44]) * 256
				ciphercount += int(payload[45])
				fmt.Printf("Got TLSv1.1 Handshake (%d ciphers) from %s to %s..\n", ciphercount/2, iplayer.SrcIP, iplayer.DstIP)
				connection.ConnectionType = "TLSv1.1"
				connection.Ciphers = getCiphers(payload[46:46+ciphercount], 2)
			} else if bytes.Compare(payload[0:3], []byte{0x16, 0x03, 0x02}) == 0 && payload[5] == 0x01 {
				ciphercount := int(payload[44]) * 256
				ciphercount += int(payload[45])
				fmt.Printf("Got TLSv1.2 Handshake (%d ciphers) from %s to %s..\n", ciphercount/2, iplayer.SrcIP, iplayer.DstIP)
				connection.ConnectionType = "TLSv1.2"
				connection.Ciphers = getCiphers(payload[46:46+ciphercount], 2)
			} else {
				return Connection{}, fmt.Errorf("Not a valid handshake")
			}
			for _, c := range connection.Ciphers {
				bits, _ := strconv.Atoi(c.Bits)
				if c.Name != "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" && (strings.Contains(c.Name, "SSL") || bits < 128 || strings.Contains(c.MAC, "MD5")) {
					color.Red(fmt.Sprintf("%+v\n", c))
					// fmt.Printf("%+v\n", c)
				} else {
					color.Green(fmt.Sprintf("%+v\n", c))
				}

			}

			return connection, nil
		}
		return Connection{}, fmt.Errorf("Not an enough data..")
	}
	return Connection{}, fmt.Errorf("Could not parse packet")
}

func getCiphers(payload []byte, step int) []Cipher {
	var ciphers []Cipher

	for i := 0; i < len(payload); i = i + step {

		c, err := findCipher(payload[i : i+step])
		if err == nil {
			ciphers = append(ciphers, c)
		} else {
			fmt.Printf("Error: %s\n", err)
		}
	}
	return ciphers
}

func findCipher(in []byte) (Cipher, error) {

	var code string

	if len(in) == 2 {
		code = strings.ToUpper(fmt.Sprintf("%02x%02x", in[0], in[1]))
		code = "0x00" + code
	} else {
		code = strings.ToUpper(fmt.Sprintf("%02x%02x%02x", in[0], in[1], in[2]))
		code = "0x" + code
	}

	for _, c := range Ciphers {
		if c.Code == code {
			return c, nil
		}
	}
	return Cipher{}, fmt.Errorf("Unkown cipher: %s", code)
}
