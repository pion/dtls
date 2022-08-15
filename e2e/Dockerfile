FROM docker.io/library/golang:1.19-bullseye

COPY . /go/src/github.com/pion/dtls
WORKDIR /go/src/github.com/pion/dtls/e2e

CMD ["go", "test", "-tags=openssl", "-v", "."]
