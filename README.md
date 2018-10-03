Simple Golang DTLS implementation to be imported into pion-WebRTC
Don't depend on this, it will be orphaned/deleted after it lands

# OpenSSL
```
  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
  openssl s_server -cert cert.pem -key key.pem -dtls1 -accept 4444
  openssl s_client -dtls1 -connect 127.0.0.1:4444 -debug -cert cert.pem -key key.pem
```
