FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
RUN apk add --no-cache conntrack-tools iproute2 nftables tcpdump
COPY test/lab/router/entrypoint.sh /usr/local/bin/lab-router
RUN chmod 0755 /usr/local/bin/lab-router
ENTRYPOINT ["/usr/local/bin/lab-router"]
