Simple Golang DTLS 1.2 implementation, this is a WIP. The intended user is pion-WebRTC, but I would love to see everyone use it.

My goal is to put this into x/net, but make it available here for now to iterate quickly

# Goals/Progress
This will only be targeting DTLS 1.2, and the most modern/common cipher suites.
I am happy to accept contributions for older implementations, but won't be implementing it myself

# Current features
* DTLS 1.2 Client/Server (No DTLS 1.0)
* Forward secrecy using ECDHE; with curve25519 (non-PFS will not be supported)
* AES_128_GCM (More ciphers welcome!)

# Testing it out
## OpenSSL
```
  // Generate a certificate
  openssl ecparam -out key.pem -name prime256v1 -genkey
  openssl req -new -sha256 -key key.pem -out server.csr
  openssl x509 -req -sha256 -days 365 -in server.csr -signkey key.pem -out cert.pem

  // Use with pions/dtls client.go
  openssl s_server -dtls1_2 -cert cert.pem -key key.pem -accept 4444

  // Use with pions/dtls server.go
  openssl s_client -dtls1_2 -connect 127.0.0.1:4444 -debug -cert cert.pem -key key.pem
```

## Golang
```sh
go run server.go
```

```sh
go run client.go
```
