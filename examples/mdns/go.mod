module github.com/pion/dtls/v3/examples/mdns

go 1.24.0

require (
	github.com/pion/dtls/v3 v3.1.8
	github.com/pion/mdns/v2 v2.2.0
	golang.org/x/net v0.49.0
)

replace github.com/pion/dtls/v3 => ../../

require (
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.1.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
