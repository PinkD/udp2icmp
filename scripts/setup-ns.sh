#!/bin/bash

set -e

DEFAULT_PREFIX="test-ns"
addr1="172.20.1.1"
addr2="172.20.1.2"

if [[ "$UID" -ne 0 ]]
then
    exec sudo "$0" "$@"
fi

ip() {
    echo "[#] ip" "$@"
    command ip "$@"
}

ipns() {
    ip -n "$@"
}

cmd_create() {
    local prefix="${1:-$DEFAULT_PREFIX}"
    local ns1="${prefix}-1"
    local ns2="${prefix}-2"

    ip netns add "$ns1"
    ip netns add "$ns2"

    local veth1="${prefix}-veth1"
    local veth2="${prefix}-veth2"
    ip link add "$veth1" type veth peer name "$veth2"

    ip link set "$veth1" netns "$ns1"
    ip link set "$veth2" netns "$ns2"

    ipns "$ns1" link set "$veth1" name eth0
    ipns "$ns1" addr add $addr1/24 dev eth0
    ipns "$ns1" link set eth0 up

    ipns "$ns2" link set "$veth2" name eth0
    ipns "$ns2" addr add $addr2/24 dev eth0
    ipns "$ns2" link set eth0 up

    echo "$ns1($addr1) <-> $ns2($addr2)"
}

cmd_enter() {
    local ns="${1:-${DEFAULT_PREFIX}-1}"
    # ensure namespace exists
    [ ! -f "/run/netns/$ns" ] && cmd_create
    ip netns exec "$ns" /bin/bash
}

cmd_destroy() {
    local prefix="${1:-$DEFAULT_PREFIX}"
    local ns1="${prefix}-1"
    local ns2="${prefix}-2"

    [ -f "/run/netns/$ns1" ] && ip netns del "$ns1"
    [ -f "/run/netns/$ns2" ] && ip netns del "$ns2"
}

case "${1:-}" in
    create|setup|init)
        cmd_create "${2:-}"
        ;;
    enter)
        cmd_enter "${2:-}"
        ;;
    destroy)
        cmd_destroy "${2:-}"
        ;;
    *)
        echo "Usage: $0 [create/setup/init [prefix] | enter [namespace] | destroy [prefix]]"
        exit 1
        ;;
esac
