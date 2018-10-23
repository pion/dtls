Simple Golang DTLS implementation to be imported into pion-WebRTC
Don't depend on this, it will be orphaned/deleted after it lands

# OpenSSL
```
  openssl ecparam -out key.pem -name prime256v1 -genkey
  openssl req -new -sha256 -key key.pem -out server.csr
  openssl x509 -req -sha256 -days 365 -in server.csr -signkey key.pem -out cert.pem

  openssl s_server -dtls1_2 -cert cert.pem -key key.pem -accept 4444
  openssl s_client -dtls1_2 -connect 127.0.0.1:4444 -debug -cert cert.pem -key key.pem
```

# Run the example

```sh
go run server.go
```

```sh
go run client.go
```

# Design/Architecture
