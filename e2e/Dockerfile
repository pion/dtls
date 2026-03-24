# SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

FROM docker.io/library/golang:1.26-trixie

# Enable OpenSSL legacy provider for CCM ciphers
#
# OpenSSL 3.x moved CCM (and other older ciphers) to the "legacy"
# provider. By default, only the "default" provider is enabled.
RUN cat <<EOF >> /etc/ssl/openssl.cnf

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

EOF

COPY . /go/src/github.com/pion/dtls
WORKDIR /go/src/github.com/pion/dtls/e2e

CMD ["go", "test", "-tags=openssl", "-v", "."]
