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
#   NXCT_SERVICE_MTLS      false  false | all | selective
#                                 all       = require a client cert on every vhost
#                                 selective = only publish the CA; add
#                                             "ssl_verify_client on;" per vhost
#   NXCT_SERVICE_MTLS_CA          Client CA, default /certs/client-ca.pem
#   NXCT_SERVICE_TLS_CATCHALL
#                          false  Reject unknown/absent SNI on 443 at handshake
#
# Client certs are issued with mtls.sh.
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

#
# NXCT_SERVICE_MTLS - client certificate authentication
#

NXCT_SERVICE_MTLS="${NXCT_SERVICE_MTLS,,}"
case "$NXCT_SERVICE_MTLS" in
  ""|false|no) NXCT_SERVICE_MTLS="no" ;;
  selective)   NXCT_SERVICE_MTLS="selective" ;;
  *)           NXCT_SERVICE_MTLS="all" ;;
esac
NXCT_SERVICE_MTLS_CA="${NXCT_SERVICE_MTLS_CA:-/certs/client-ca.pem}"
MTLS_DIR="${NXCT_SERVICE_MTLS_DIR:-/certs/.mtls}"

if [ "$NXCT_SERVICE_MTLS" != "no" ]; then
  if [ ! -s "$NXCT_SERVICE_MTLS_CA" ]; then
    echo "ERROR: NXCT_SERVICE_MTLS is on but $NXCT_SERVICE_MTLS_CA is missing - run mtls.sh init" >&2
    exit 3
  fi
  echo "Hardening: mTLS ($NXCT_SERVICE_MTLS), client CA $NXCT_SERVICE_MTLS_CA"
  # Port 80 is unaffected either way, so the ACME http-01 challenge keeps working.
  # On its own ssl_client_certificate sends no CertificateRequest, so in selective
  # mode public vhosts behave exactly as before.
  MTLS_CONF="    ssl_client_certificate $NXCT_SERVICE_MTLS_CA;"
  if [ "$NXCT_SERVICE_MTLS" = "all" ]; then
    MTLS_CONF="$MTLS_CONF
    ssl_verify_client on;"
  fi
  hardening_insert_http "nginxcrypt hardening: mtls" "$MTLS_CONF"

  # upstream_monitor.sh probes vhosts over HTTPS from loopback. Without a client
  # cert the handshake is rejected, the probe returns 000 and the domain is
  # alerted as down. curl reads ~/.curlrc, so it can be given one without
  # touching upstream_monitor.sh.
  if [ -s "$MTLS_DIR/monitor-cert.pem" ] && [ -s "$MTLS_DIR/monitor-key.pem" ]; then
    if ! grep -qs "$MTLS_DIR/monitor-cert.pem" /root/.curlrc; then
      printf 'cert = %s\nkey = %s\n' \
        "$MTLS_DIR/monitor-cert.pem" "$MTLS_DIR/monitor-key.pem" >> /root/.curlrc
    fi
  else
    echo "WARNING: no monitor client cert, domain probes will report false outages" >&2
  fi
fi

#
# NXCT_SERVICE_TLS_CATCHALL - reject unknown SNI before the handshake completes
#

NXCT_SERVICE_TLS_CATCHALL=$(hardening_bool "$NXCT_SERVICE_TLS_CATCHALL")

if [ "$NXCT_SERVICE_TLS_CATCHALL" = "yes" ]; then
  # Without this, the first vhost nginx parses becomes the implicit default for
  # :443, so a scanner with no SNI gets a full handshake and that vhost's cert.
  # A second default_server on 443 is a fatal config error, so bail if a vhost
  # already claims one.
  if grep -rqsE 'listen[^;]*443[^;]*default_server' /etc/nginx/conf.d/; then
    echo "WARNING: a vhost already claims default_server on 443, skipping TLS catch-all" >&2
  else
    echo "Hardening: TLS catch-all enabled (unknown SNI rejected at handshake)"
    hardening_insert_http "nginxcrypt hardening: tls catch-all" \
"    server {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        ssl_reject_handshake on;
    }"
  fi
fi

exec "$ENTRYPOINT" "$@"
