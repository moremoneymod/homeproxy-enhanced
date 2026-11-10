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
	IPS4=$(resolveip -4 -t 5 "$host" 2>/dev/null | sort -u)
	IPS6=$(resolveip -6 -t 5 "$host" 2>/dev/null | sort -u)
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
	[ "$direct_ready" -eq 1 ] || { echo 'stage=route error=direct_set_unavailable' >&2; exit 4; }
fi

set -- /usr/bin/wget -S -O "$TMP.body" --user-agent "$UA" --timeout=35 "$@" "$URL"
"$@" 2>"$TMP.headers"
rc=$?
status=$(sed -n 's/^[[:space:]]*HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' "$TMP.headers" | tail -1)
bytes=$(wc -c < "$TMP.body" 2>/dev/null || echo 0)
[ -n "$status" ] || status=unknown
echo "stage=http route=$MODE status=$status wget_exit=$rc bytes=$bytes" >&2
[ "$rc" -eq 0 ] || exit "$rc"
cat "$TMP.body"
