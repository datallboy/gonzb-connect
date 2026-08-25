FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
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
