#!/bin/sh
set -eu
for family in iptables ip6tables; do
  command -v "$family" >/dev/null
  "$family" -w -N PacketTale-In 2>/dev/null || true
  "$family" -w -C PacketTale-In -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "$family" -w -A PacketTale-In -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  "$family" -w -C PacketTale-In -i lo -j ACCEPT 2>/dev/null || "$family" -w -A PacketTale-In -i lo -j ACCEPT
  "$family" -w -C PacketTale-In -p tcp --dport 22 -j ACCEPT 2>/dev/null || "$family" -w -A PacketTale-In -p tcp --dport 22 -j ACCEPT
  if [ "$family" = iptables ]; then
    "$family" -w -C PacketTale-In -p icmp -j ACCEPT 2>/dev/null || "$family" -w -A PacketTale-In -p icmp -j ACCEPT
    "$family" -w -C PacketTale-In -p udp --sport 67 --dport 68 -j ACCEPT 2>/dev/null || "$family" -w -A PacketTale-In -p udp --sport 67 --dport 68 -j ACCEPT
  else
    "$family" -w -C PacketTale-In -p ipv6-icmp -j ACCEPT 2>/dev/null || "$family" -w -A PacketTale-In -p ipv6-icmp -j ACCEPT
    "$family" -w -C PacketTale-In -p udp --sport 547 --dport 546 -j ACCEPT 2>/dev/null || "$family" -w -A PacketTale-In -p udp --sport 547 --dport 546 -j ACCEPT
  fi
  "$family" -w -C PacketTale-In -j DROP 2>/dev/null || "$family" -w -A PacketTale-In -j DROP
  "$family" -w -C INPUT -j PacketTale-In 2>/dev/null || "$family" -w -I INPUT 1 -j PacketTale-In
done
