#!/bin/sh
# Always-on diagnostic wrapper. It records loader/compiler failures which the
# ucode program itself cannot log because execution has not started yet.

LOG=/var/run/homeproxy/subscription.log
mkdir -p /var/run/homeproxy
printf '%s [LAUNCHER] Starting subscription updater.\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"

LOCK=/var/run/homeproxy/subscription-update.lock
if ! command -v flock >/dev/null 2>&1; then
	printf '%s [LAUNCHER] ERROR: flock is required for safe synchronization.\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
	exit 69
fi
exec 9>"$LOCK"
flock -n 9 || {
	printf '%s [LAUNCHER] busy: another updater is running.\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
	exit 75
}

/usr/bin/ucode /etc/homeproxy/scripts/update_subscriptions.uc "$@" 2>> "$LOG"
rc=$?

printf '%s [LAUNCHER] Updater exited with code %s.\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$rc" >> "$LOG"
exit "$rc"
