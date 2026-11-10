#!/bin/sh
# Always-on diagnostic wrapper. It records loader/compiler failures which the
# ucode program itself cannot log because execution has not started yet.

LOG=/var/run/homeproxy/subscription.log
mkdir -p /var/run/homeproxy
printf '%s [LAUNCHER] Starting subscription updater.\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"

/usr/bin/ucode /etc/homeproxy/scripts/update_subscriptions.uc "$@" 2>> "$LOG"
rc=$?

printf '%s [LAUNCHER] Updater exited with code %s.\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$rc" >> "$LOG"
exit "$rc"
