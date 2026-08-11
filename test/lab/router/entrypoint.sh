#!/bin/sh
set -eu

: "${LAB_LAN_ADDRESS:?LAB_LAN_ADDRESS is required}"
: "${LAB_LAN_CIDR:?LAB_LAN_CIDR is required}"
: "${LAB_WAN_ADDRESS:?LAB_WAN_ADDRESS is required}"
: "${LAB_WAN_CIDR:?LAB_WAN_CIDR is required}"
: "${LAB_PEER_ADDRESS:?LAB_PEER_ADDRESS is required}"

find_interface() {
  address="$1"
  ip -o -4 address show | awk -v address="$address" '$4 ~ ("^" address "/") { print $2; exit }'
}

lan_if=$(find_interface "$LAB_LAN_ADDRESS")
wan_if=$(find_interface "$LAB_WAN_ADDRESS")
if [ -z "$lan_if" ] || [ -z "$wan_if" ] || [ "$lan_if" = "$wan_if" ]; then
  echo "could not identify distinct lab LAN and WAN interfaces" >&2
  ip -o address show >&2
  exit 1
fi

if [ -n "${LAB_UPSTREAM_GATEWAY:-}" ]; then
  ip route replace default via "$LAB_UPSTREAM_GATEWAY" dev "$wan_if"
fi

policy=${LAB_POLICY:-home-nat}
case "$policy" in
  home-nat|symmetric-nat|turn-udp-only|turn-tls-only|turn-tls-blackhole) ;;
  *)
    echo "unsupported lab router policy: $policy" >&2
    exit 1
    ;;
esac

cat >/tmp/lab-router.nft <<EOF
flush ruleset

table inet lab_filter {
  chain input {
    type filter hook input priority filter; policy accept;
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
EOF

if [ "$policy" = "home-nat" ]; then
  echo "    iifname \"$wan_if\" oifname \"$lan_if\" ip daddr $LAB_PEER_ADDRESS meta l4proto udp accept" >>/tmp/lab-router.nft
fi

cat >>/tmp/lab-router.nft <<EOF
    iifname "$lan_if" oifname "$wan_if" ip saddr $LAB_LAN_CIDR jump outbound
  }

  chain outbound {
EOF

case "$policy" in
  home-nat|symmetric-nat)
    cat >>/tmp/lab-router.nft <<EOF
    ip daddr 10.0.0.0/8 drop
    accept
EOF
    ;;
  turn-udp-only)
    cat >>/tmp/lab-router.nft <<EOF
    ip daddr ${LAB_CONNECT_ADDRESS:-172.30.0.10} tcp dport 443 accept
    ip daddr ${LAB_TURN_ADDRESS:-172.30.0.20} accept
    ip daddr $LAB_WAN_CIDR drop
    ip daddr 10.0.0.0/8 drop
    accept
EOF
    ;;
  turn-tls-only)
    cat >>/tmp/lab-router.nft <<EOF
    ip daddr ${LAB_CONNECT_ADDRESS:-172.30.0.10} tcp dport 443 accept
    ip daddr ${LAB_TURN_ADDRESS:-172.30.0.20} tcp dport 5349 accept
    meta l4proto udp reject with icmp type port-unreachable
    ip daddr $LAB_WAN_CIDR meta l4proto tcp reject with tcp reset
    ip daddr $LAB_WAN_CIDR reject
    ip daddr 10.0.0.0/8 drop
    accept
EOF
    ;;
  turn-tls-blackhole)
    cat >>/tmp/lab-router.nft <<EOF
    ip daddr ${LAB_CONNECT_ADDRESS:-172.30.0.10} tcp dport 443 accept
    ip daddr ${LAB_TURN_ADDRESS:-172.30.0.20} tcp dport 5349 accept
    meta l4proto udp drop
    ip daddr $LAB_WAN_CIDR drop
    ip daddr 10.0.0.0/8 drop
    accept
EOF
    ;;
esac

cat >>/tmp/lab-router.nft <<EOF
  }
}

table ip lab_nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
EOF

if [ "$policy" = "home-nat" ]; then
  echo "    iifname \"$wan_if\" ip daddr $LAB_WAN_ADDRESS meta l4proto udp dnat to $LAB_PEER_ADDRESS" >>/tmp/lab-router.nft
fi

cat >>/tmp/lab-router.nft <<EOF
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
EOF

if [ "$policy" = "symmetric-nat" ]; then
  echo "    oifname \"$wan_if\" ip saddr $LAB_LAN_CIDR masquerade fully-random" >>/tmp/lab-router.nft
else
  echo "    oifname \"$wan_if\" ip saddr $LAB_LAN_CIDR masquerade" >>/tmp/lab-router.nft
fi

cat >>/tmp/lab-router.nft <<EOF
  }
}
EOF

nft -f /tmp/lab-router.nft
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
  echo "IPv4 forwarding is disabled in the router namespace" >&2
  exit 1
fi

echo "lab router ready policy=$policy lan=$lan_if/$LAB_LAN_ADDRESS wan=$wan_if/$LAB_WAN_ADDRESS"
exec tail -f /dev/null
