FROM golang:alpine AS builder

ENV GO111MODULE="on"
ENV CGO_ENABLED="0"

RUN apk add --update git

RUN mkdir -p /go/src/github.com/DeviaVir/gpg-prometheus-exporter

COPY . /go/src/github.com/DeviaVir/gpg-prometheus-exporter

RUN cd /go/src/github.com/DeviaVir/gpg-prometheus-exporter \
 && go mod vendor \
 && go build \
      -mod vendor \
      -o /go/bin/gpg-prometheus-exporter

FROM alpine
COPY --from=builder /go/bin/gpg-prometheus-exporter /usr/local/bin/gpg-prometheus-exporter
CMD ["/usr/local/bin/gpg-prometheus-exporter"]
