#!/bin/bash
#
# Post-generation hook, sourced by entrypoint.sh once the N.conf files exist.
# Applies options that need server context and therefore cannot be injected into
# nginx.conf the way hardening.sh does.
#
# Re-applied on every start, so config regeneration cannot strand them.
#
# Options:
#   NXCT_SERVICE_MTLS_<N>  false  Require a client certificate on
#                                 NXCT_SERVICE_HOST_<N>. Needs NXCT_SERVICE_MTLS
#                                 set (selective or all) and a writable /conf.
#

# Pseudo boolean, same rules as entrypoint.sh
# $1 = raw value
hardening_post_bool() {
  local val="${1,,}"
  if [ -z "$val" ] || [ "$val" = "false" ] || [ "$val" = "no" ]; then
    echo "no"
  else
    echo "yes"
  fi
}

for hardening_post_svc in $(env | grep '^NXCT_SERVICE_HOST_' | cut -d "=" -f1 | sed 's/^NXCT_SERVICE_HOST_//'); do
  hardening_post_flag="NXCT_SERVICE_MTLS_$hardening_post_svc"
  [ "$(hardening_post_bool "${!hardening_post_flag}")" = "yes" ] || continue

  hardening_post_hostvar="NXCT_SERVICE_HOST_$hardening_post_svc"
  hardening_post_host="${!hardening_post_hostvar}"
  hardening_post_file="/conf/$(echo "$hardening_post_svc" | tr '[:upper:]' '[:lower:]').conf"

  # Fail closed. Carrying on would leave a vhost the operator believes is
  # protected silently serving anonymous traffic.
  if [ -z "$NXCT_SERVICE_MTLS" ] || [ "${NXCT_SERVICE_MTLS,,}" = "false" ] || [ "${NXCT_SERVICE_MTLS,,}" = "no" ]; then
    die "ERROR: $hardening_post_flag is set but NXCT_SERVICE_MTLS is off - no client CA would be configured"
  fi
  if [ ! -f "$hardening_post_file" ]; then
    die "ERROR: $hardening_post_flag is set but $hardening_post_file does not exist"
  fi
  if grep -q 'ssl_verify_client' "$hardening_post_file"; then
    continue
  fi
  if [ ! -w "$hardening_post_file" ]; then
    die "ERROR: cannot enable mTLS on $hardening_post_host - $hardening_post_file is read-only. Mount /conf writable or add 'ssl_verify_client on;' by hand."
  fi

  # ssl_dhparam appears exactly once per generated file, inside the 443 server
  # block, so it is a reliable anchor in both the min and api templates.
  hardening_post_tmp=$(mktemp) || die "ERROR: mktemp failed"
  awk '/ssl_dhparam/ && !done { print; print "  ssl_verify_client on;"; done=1; next } { print }' \
    "$hardening_post_file" > "$hardening_post_tmp" && cat "$hardening_post_tmp" > "$hardening_post_file"
  rm -f "$hardening_post_tmp"
  echo "Hardening: mTLS required on $hardening_post_host ($hardening_post_file)"
done
