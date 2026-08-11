#!/bin/sh
set -eu

if [ -n "${LAB_GATEWAY:-}" ]; then
  ip route replace default via "$LAB_GATEWAY"
  default_route=$(ip -4 route show default)
  case "$default_route" in
    "default via $LAB_GATEWAY "*) ;;
    *)
      echo "lab peer default route did not move to $LAB_GATEWAY" >&2
      exit 1
      ;;
  esac
fi

exec su-exec 1000:1000 /usr/local/bin/gonzb-connect-lab-peer "$@"
