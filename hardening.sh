#!/bin/bash
#
# Optional hardening layer. Runs as ENTRYPOINT, applies enabled options, then
# execs entrypoint.sh. All options are opt-in, so unconfigured it is a no-op.
#
# Writes to /etc/nginx/nginx.conf, never /conf, so it works with conf mounted :ro.
#
# Options:
#   NXCT_SERVICE_FILELOG   false  Also log to files (for fail2ban etc.)
#   NXCT_SERVICE_LOGDIR    /logs  Where those files go
#

ENTRYPOINT="/root/.acme.sh/entrypoint.sh"
NGINX_CONF="/etc/nginx/nginx.conf"

# Pseudo boolean, same rules as entrypoint.sh
# $1 = raw value
hardening_bool() {
  local val="${1,,}"
  if [ -z "$val" ] || [ "$val" = "false" ] || [ "$val" = "no" ]; then
    echo "no"
  else
    echo "yes"
  fi
}

# Insert config into the http block, above the conf.d include - not below
# "http {", where log_format 'main' is not declared yet.
# $1 = marker (keeps it idempotent), $2 = config to insert
hardening_insert_http() {
  local marker="$1"
  local payload="$2"
  local tmp

  if grep -qF "$marker" "$NGINX_CONF"; then
    return 0
  fi
  if ! grep -q 'include /etc/nginx/conf.d/\*.conf;' "$NGINX_CONF"; then
    echo "WARNING: no conf.d include in $NGINX_CONF, skipping '$marker'" >&2
    return 1
  fi

  tmp=$(mktemp) || return 1
  # awk, not sed: the payload is multi-line
  awk -v marker="$marker" -v payload="$payload" '
    /include \/etc\/nginx\/conf\.d\/\*\.conf;/ && !done {
      print "    # " marker
      print payload
      print ""
      done = 1
    }
    { print }
  ' "$NGINX_CONF" > "$tmp" && cat "$tmp" > "$NGINX_CONF"
  rm -f "$tmp"
}

#
# NXCT_SERVICE_FILELOG - file based logging
#

NXCT_SERVICE_FILELOG=$(hardening_bool "$NXCT_SERVICE_FILELOG")
NXCT_SERVICE_LOGDIR="${NXCT_SERVICE_LOGDIR:-/logs}"

if [ "$NXCT_SERVICE_FILELOG" = "yes" ]; then
  if [[ "$NXCT_SERVICE_LOGDIR" != /* ]]; then
    echo "ERROR: NXCT_SERVICE_LOGDIR must be an absolute path: $NXCT_SERVICE_LOGDIR" >&2
    exit 3
  fi
  # nginx will not start if the log dir is missing (e.g. no volume mounted)
  mkdir -p "$NXCT_SERVICE_LOGDIR"
  echo "Hardening: file based logging enabled in $NXCT_SERVICE_LOGDIR"
  # /var/log/nginx/error.log is repeated on purpose: an http level error_log
  # overrides the main level one, which would silence container stderr.
  hardening_insert_http "nginxcrypt hardening: file logging" \
"    access_log $NXCT_SERVICE_LOGDIR/access.log main;
    error_log /var/log/nginx/error.log warn;
    error_log $NXCT_SERVICE_LOGDIR/error.log warn;"
fi

exec "$ENTRYPOINT" "$@"
