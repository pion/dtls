# Certificates

The certificates in for the examples are generated using the commands shown below.

Note that this was run on OpenSSL 1.1.1d, of which the arguments can be found in the [OpenSSL Manpages](ttps://www.openssl.org/docs/man1.1.1/man1), and is not guaranteed to work on different OpenSSL versions.

```shell
$ NAME='server'
$ openssl ecparam -name prime256v1 -genkey -noout -out "${NAME}.pem"
$ openssl req -key "${NAME}.pem" -new -sha256 -subj '/C=NL' -out "${NAME}.csr"
$ openssl x509 -req -in "${NAME}.csr" -days 365 -signkey "${NAME}.pem" -sha256 -out "${NAME}.pub.pem"
$ rm "${NAME}.csr"  # Cleanup
```

