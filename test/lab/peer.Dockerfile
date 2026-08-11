FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY client ./client
COPY ice ./ice
COPY protocol ./protocol
COPY cmd/gonzb-connect-lab-peer ./cmd/gonzb-connect-lab-peer
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/gonzb-connect-lab-peer ./cmd/gonzb-connect-lab-peer

FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
RUN apk add --no-cache ca-certificates iproute2 su-exec
COPY --from=build /out/gonzb-connect-lab-peer /usr/local/bin/gonzb-connect-lab-peer
COPY test/lab/peer-entrypoint.sh /usr/local/bin/peer-entrypoint
RUN chmod 0755 /usr/local/bin/peer-entrypoint
ENTRYPOINT ["/usr/local/bin/peer-entrypoint"]
