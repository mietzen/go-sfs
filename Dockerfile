FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git openssl
WORKDIR $GOPATH/src/mietzen/go-sfs/
COPY . .
RUN go get -d -v
RUN go test
RUN go build -o /tmp/file-server

FROM scratch

COPY --from=builder /tmp/file-server /file-server
EXPOSE 8080
VOLUME [ "/config", "/data" ]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD [ "/file-server", "--health" ]

ENTRYPOINT ["/file-server"]