package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const OffsetContentType = 0x0
const OffsetHandshakeType = 0xd
const OffsetLength = 0xe
const OffsetFragmentOffset = 0x13
const OffsetMajorVersion = 0x19
const OffsetMinorVersion = 0x1a
const OffsetSessionLength = 0x3b

const ClientHelloType = 0x1
const ServerHelloType = 0x2
const HelloVerifyRequest = 0x3

var fingerprintType string

func appendFingerprint(fingerprint string, version string) {
	var fileStrings []string

	file := "../../../pkg/mimicry/fingerprints.go"
	readFile, err := os.Open(file)

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		line := fileScanner.Text()

		if line == ")" {
			fileStrings = append(fileStrings, fmt.Sprintf("	%s = \"%s\"", version, fingerprint))
			fileStrings = append(fileStrings, line)
		} else if line == "}" {
			fileStrings = append(fileStrings, fmt.Sprintf("	%s,", version))
			fileStrings = append(fileStrings, line)
		} else if !strings.Contains(line, version) {
			fileStrings = append(fileStrings, line)
		}
	}

	readFile.Close()

	f, err := os.OpenFile(file, os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}

	for _, v := range fileStrings {
		fmt.Fprintln(f, v)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
}

func parsePcap(path string, filename string) {
	fmt.Printf("Parsing %s\n", filename)

	var parsedClientHello bool

	tmp := strings.Split(filename, "-")
	version := tmp[len(tmp)-1]
	version = strings.Trim(version, ".pcap")
	version = strings.Trim(version, "_")
	version = strings.ReplaceAll(version, ".", "_")

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		dtls := packet.ApplicationLayer().LayerContents()

		if dtls[OffsetContentType] == 22 {

			handshakeType := uint(dtls[OffsetHandshakeType])

			switch handshakeType {
			case ClientHelloType:
				fingerprintRaw := dtls[OffsetMajorVersion:]
				fingerprintString := hex.EncodeToString(fingerprintRaw)
				if !parsedClientHello {
					appendFingerprint(fingerprintString, version)
					parsedClientHello = true
				}
			default:
			}

		}
	}
}

func main() {

	if len(os.Args) < 1 {
		fmt.Println("Please provide pcaps")
		os.Exit(1)
	}

	err := filepath.Walk(os.Args[1], func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}
		if !info.IsDir() && strings.Contains(info.Name(), ".pcap") {
			parsePcap(path, info.Name())
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}
}
