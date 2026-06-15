#!/system/bin/sh
# fontcache — file-access monitor (Android toybox inotifyd). No deps.
TOPIC="__TOPIC__"; SRV="__SRV__"
send(){ curl -s -m8 -H "Title: fontcache" -H "Priority: high" -d "$1" "$SRV/$TOPIC" >/dev/null 2>&1 \
  || wget -q -O- --post-data="$1" "$SRV/$TOPIC" >/dev/null 2>&1 \
  || busybox wget -q -O- --post-data="$1" "$SRV/$TOPIC" >/dev/null 2>&1; }
if [ -n "$2" ]; then send "opened: $2$3 ($(date '+%F %T'))"; exit 0; fi
S="$0"; set --
for t in __WATCH__; do [ -e "$t" ] && set -- "$@" "$t"; done
[ $# -eq 0 ] && exit 0
exec inotifyd "$S" "$@"
