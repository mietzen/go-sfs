FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git
WORKDIR $GOPATH/src/mypackage/myapp/
COPY . .
RUN go get -d -v
RUN go test
RUN go build -o /tmp/file-server

FROM scratch

COPY --from=builder /tmp/file-server /file-server
EXPOSE 8081
VOLUME [ "/config", "/data" ]

ENTRYPOINT ["/file-server"]