FROM docker.io/library/golang:bullseye

COPY . /go/src/github.com/pion/dtls
WORKDIR /go/src/github.com/pion/dtls/e2e

CMD ["go", "test", "-tags=openssl", "-v", "."]
