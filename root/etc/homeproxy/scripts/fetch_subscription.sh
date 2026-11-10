#!/bin/sh
# Fetch one subscription without stopping HomeProxy. For direct downloads the
# provider IPs are temporarily inserted into HomeProxy's existing direct sets.

MODE=$1
URL=$2
UA=$3
shift 3

TMP="/tmp/homeproxy-sub-fetch.$$"
ADDED4=""
ADDED6=""

cleanup() {
	for ip in $ADDED4; do
		nft delete element inet fw4 homeproxy_wan_direct_addr_v4 "{ $ip }" 2>/dev/null
	done
	for ip in $ADDED6; do
		nft delete element inet fw4 homeproxy_wan_direct_addr_v6 "{ $ip }" 2>/dev/null
	done
	rm -f "$TMP.body" "$TMP.headers"
}
trap cleanup EXIT INT TERM

if [ "$MODE" = direct ]; then
	direct_ready=0
	authority=${URL#*://}
	authority=${authority%%/*}
	authority=${authority##*@}
	case "$authority" in
		\[*\]*) host=${authority#\[}; host=${host%%\]*} ;;
		*) host=${authority%%:*} ;;
	esac

	[ -n "$host" ] || { echo 'stage=resolve error=invalid_host' >&2; exit 2; }
	IPS4=""
	IPS6=""
	if command -v resolveip >/dev/null 2>&1; then
		IPS4=$(resolveip -4 -t 5 "$host" 2>/dev/null | sort -u)
		IPS6=$(resolveip -6 -t 5 "$host" 2>/dev/null | sort -u)
	fi
	if [ -z "$IPS4$IPS6" ] && command -v nslookup >/dev/null 2>&1; then
		# Query the ISP/WAN resolver explicitly. This remains usable when dnsmasq
		# was previously configured to forward through a now-stopped proxy core.
		WAN_DNS=$(ubus call network.interface.wan status 2>/dev/null \
			| jsonfilter -e '@["dns-server"][0]' 2>/dev/null)
		[ -n "$WAN_DNS" ] || WAN_DNS=$(awk '/^nameserver[[:space:]]/ { print $2; exit }' \
			/tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null)
		DNS_LIST="$WAN_DNS 1.1.1.1 8.8.8.8 9.9.9.9"
		for dns in $DNS_LIST; do
			[ -n "$dns" ] || continue
			LOOKUP=$(nslookup "$host" "$dns" 2>/dev/null)
			CANDIDATES=$(printf '%s\n' "$LOOKUP" | awk '
				/^Name:/ { seen=1; next }
				seen && /^Address([[:space:]][0-9]+)?:/ { print $NF }
			')
			IPS4=$(printf '%s\n' "$CANDIDATES" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u)
			IPS6=$(printf '%s\n' "$CANDIDATES" | grep ':' | sort -u)
			if [ -n "$IPS4$IPS6" ]; then
				echo "stage=resolve dns=$dns ipv4=$(printf '%s' "$IPS4" | tr '\n' ',') ipv6=$(printf '%s' "$IPS6" | tr '\n' ',')" >&2
				break
			fi
		done
	fi
	[ -n "$IPS4$IPS6" ] || { echo 'stage=resolve error=no_address' >&2; exit 3; }

	if nft list set inet fw4 homeproxy_wan_direct_addr_v4 >/dev/null 2>&1; then
		[ -n "$IPS4" ] && direct_ready=1
		for ip in $IPS4; do
			if ! nft get element inet fw4 homeproxy_wan_direct_addr_v4 "{ $ip }" >/dev/null 2>&1; then
				nft add element inet fw4 homeproxy_wan_direct_addr_v4 "{ $ip }" 2>/dev/null && ADDED4="$ADDED4 $ip"
			fi
		done
	fi
	if nft list set inet fw4 homeproxy_wan_direct_addr_v6 >/dev/null 2>&1; then
		[ -n "$IPS6" ] && direct_ready=1
		for ip in $IPS6; do
			if ! nft get element inet fw4 homeproxy_wan_direct_addr_v6 "{ $ip }" >/dev/null 2>&1; then
				nft add element inet fw4 homeproxy_wan_direct_addr_v6 "{ $ip }" 2>/dev/null && ADDED6="$ADDED6 $ip"
			fi
		done
	fi
	if [ "$direct_ready" -ne 1 ]; then
		# No HomeProxy firewall means there is nothing to bypass: this is already a
		# native WAN request (common before the first subscription imports a node).
		if pgrep -f '/usr/bin/hiddify-core' >/dev/null 2>&1 || pgrep -f '/usr/bin/sing-box' >/dev/null 2>&1; then
			echo 'stage=route error=direct_set_unavailable' >&2
			exit 4
		fi
		MODE=direct-native
	fi
fi

 : > "$TMP.body"
set -- /usr/bin/wget -O "$TMP.body" --user-agent "$UA" --timeout=35 "$@" "$URL"
"$@" 2>"$TMP.headers"
rc=$?
status=$(sed -n 's/^[[:space:]]*HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' "$TMP.headers" | tail -1)
bytes=$(wc -c < "$TMP.body" 2>/dev/null || echo 0)
[ -n "$status" ] || status=unknown
detail=$(tr '\r\n' '  ' < "$TMP.headers" 2>/dev/null | sed "s#$(printf '%s' "$URL" | sed 's/[.[\*^$()+?{|]/\\&/g')#<redacted>#g" | cut -c1-300)
echo "stage=http route=$MODE status=$status wget_exit=$rc bytes=$bytes detail=$detail" >&2
[ "$rc" -eq 0 ] || exit "$rc"
cat "$TMP.body"
