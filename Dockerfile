FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY coordinator ./coordinator
COPY protocol ./protocol
COPY cmd/gonzb-connect-coordinator ./cmd/gonzb-connect-coordinator
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/gonzb-connect-coordinator ./cmd/gonzb-connect-coordinator

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/gonzb-connect-coordinator /usr/local/bin/gonzb-connect-coordinator
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gonzb-connect-coordinator"]
