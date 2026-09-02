# DTLS handshake over mDNS

This demo carries each DTLS PSK handshake batch in an update to a DNS-SD TXT record.
The server and client run as separate processes and exchange multicast DNS
packets over the loopback interface. The same detached DTLS connection remains
in use after the handshake; each side routes its later datagrams over unicast
UDP. Before switching paths, each side confirms handshake completion in its TXT
record so an application datagram cannot overtake the peer's final handshake
batch. Interactive messages then travel over the UDP path.

Each process binds a random UDP port and advertises that port in its DNS-SD SRV
record. The peer discovers both the address and port through mDNS.

Start the server in one terminal:

```sh
go run ./server
```

Then start one or more clients in other terminals:

```sh
go run ./client
go run ./client
```

Each client advertises a unique DNS-SD instance. The server creates a separate
DTLS connection, response TXT record, and UDP socket for every client, so their
handshakes and application datagrams cannot be mixed. After they connect, a
line typed in a client is sent to the server; a line typed in the server is
broadcast to every connected client. Only the bounded handshake batches use
DNS-SD TXT updates.
