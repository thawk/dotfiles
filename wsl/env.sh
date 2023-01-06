#!/usr/bin/env bash
# Time: 2022-06-23 11:09:23

#export LOCAL_SOCKS5_PROXY=${LOCAL_SOCKS5_PROXY:-$(grep -m 1 nameserver /etc/resolv.conf | awk '{print $2}'):1080}
export LOCAL_SOCKS5_PROXY=${LOCAL_SOCKS5_PROXY:-$(hostname).local:1080}
# Remove paths that contains space, e.g. C:/Program Files/
export PATH="$(echo "$PATH" | tr ':' '\n' | grep -v ' ' | tr '\n' ':' | sed 's/:$//')"
