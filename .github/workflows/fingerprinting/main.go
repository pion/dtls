package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const OffsetContentType = 0
const OffsetHandshakeType = 13
const OffsetMajorVersion = 25

const ClientHelloType = 1
const ServerHelloType = 2
const HelloVerifyRequest = 3
const HandshakeType = 22

var fingerprintType string

func appendFingerprint(fingerprint string, version string) error {
	var fileStrings []string

	file := "../../../pkg/mimicry/fingerprints.go"
	readFile, err := os.Open(file)

	if err != nil {
		return err
	}
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		line := fileScanner.Text()

		if line == ")" {
			fileStrings = append(fileStrings, fmt.Sprintf("\t%s ClientHelloFingerprint = \"%s\"", version, fingerprint))
			fileStrings = append(fileStrings, line)
		} else if line == "\t}" {
			fileStrings = append(fileStrings, fmt.Sprintf("\t\t%s,", version))
			fileStrings = append(fileStrings, line)
		} else if !strings.Contains(line, version) {
			fileStrings = append(fileStrings, line)
		}
	}

	readFile.Close()

	f, err := os.OpenFile(file, os.O_WRONLY, 0644)
	if err != nil {
		f.Close()
		return err
	}

	for _, v := range fileStrings {
		fmt.Fprintln(f, v)
		if err != nil {
			f.Close()
			return err
		}
	}
	err = f.Close()
	return err
}

func parsePcap(path string, filename string) error {
	fmt.Printf("Parsing %s\n", filename)

	var parsedClientHello bool

	tmp := strings.Split(filename, "-")
	version := tmp[len(tmp)-1]
	version = strings.Trim(version, ".pcap")
	version = strings.Trim(version, "_")
	version = strings.ReplaceAll(version, ".", "_")

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		dtls := packet.ApplicationLayer().LayerContents()

		if len(dtls) < OffsetContentType {
			return errors.New("parsed packet is empty")
		}
		if dtls[OffsetContentType] == HandshakeType {

			if len(dtls) < OffsetHandshakeType {
				return errors.New("parsed packet does not contain a handshake")
			}
			handshakeType := uint(dtls[OffsetHandshakeType])

			switch handshakeType {
			case ClientHelloType:
				if len(dtls) < OffsetMajorVersion {
					return errors.New("parsed client hello does not have any fields")
				}
				fingerprintRaw := dtls[OffsetMajorVersion:]
				fingerprintString := hex.EncodeToString(fingerprintRaw)

				// Only parse one client hello per handshake
				if !parsedClientHello {
					err = appendFingerprint(fingerprintString, version)
					if err != nil {
						return err
					}
					parsedClientHello = true
				}
			default:
			}

		}
	}
	return nil
}

func main() {
	if len(os.Args) < 1 {
		fmt.Println("Please provide pcaps")
		os.Exit(1)
	}

	err := filepath.Walk(os.Args[1], func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.Contains(info.Name(), ".pcap") {
			err = parsePcap(path, info.Name())
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed during parsing of pcap: %v\n", err)
		os.Exit(1)
	}
}
