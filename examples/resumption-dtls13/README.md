# DetachedConn DTLS 1.3 resumption and 0-RTT

A resumption DTLS server client and server demo. The server accepts one client at a time,

On first start the server generates a self-signed localhost certificate and private
key using saving them as `server.crt` and `server.key`. Later starts reuse
them.

```sh
go run ./ -server
```

In another terminal, start the client. It prompts for the session-file passphrase, choose one on the first run and reuse it afterward:

```sh
go run ./
```

The client verifies `server.crt` for `localhost`. It saves the ticket identity,
resumption secret, and metadata to `session.enc` when you enter `/quit` or press
Ctrl+C. The file uses scrypt (N=32768, r=8, p=1), AES-256-GCM, a fresh random salt
and nonce, The passphrase encrypts the local ticket file.

## How this works

This example uses DTLS 1.3 PSK-based resumption:

- The first connection authenticates the server using its certificate and derives
  a resumption PSK associated with a session ticket.
- Later connections use the cached ticket and PSK for resumption and, optionally,
  0-RTT early data. The encrypted client file stores both the ticket and secret.

Restarting the server loses its in-memory tickets and PSKs, so an old client
ticket falls back to a full fresh certificate-authenticated handshake.

1. **First run:** both peers do full certificate handshake.
2. **Normal resumption:** restart the client with the same running server and
   session file. At the early-data prompt, press Enter to skip 0-rtt.
3. **0-RTT:** restart the client again and enter text at the early-data prompt.
   The client sends it on `DetachedEarlyDataReady`. The server prints the early
   text sent with the first epoch.
4. **Server restart:** stop and restart the server.
   Because its in-memory tickets are gone. The next client connection falls back to a
   full handshake. If early text was requested, the client retries that echo text
   after the handshake when early data is rejected or unavailable.

> [!WARNING]
> Applications must implement [`Claim`](https://github.com/pion/dtls/blob/16cc07c2682746644daa5c4297cab0468853cdfb/session.go#L79-L87)
> to enable 0-RTT. Pion requires this interface but cannot verify that the
> user's implementation provides the required single-use guarantee.
>
> `Claim` must atomically return `true` only once per ticket. Claims must be shared
> across all servers accepting those tickets and retained until `expiresAt`, even
> if the session is updated or deleted. Otherwise, the same ticket's early data
> could be accepted more than once. Claiming a ticket must preserve it for ordinary
> resumption.
>
> This local demo skips the server's cookie exchange to allow 0-RTT.
> Production deployments might need real address validation and DoS
> protection. An underlying transport such as ICE may provide address validation,
>  For most applications, prefer session resumption without 0-RTT unless your application can safely
> handle replayed requests (Implements Claim safely) and benefits from lower latency, such as an IoT
> application on a high-latency network.
