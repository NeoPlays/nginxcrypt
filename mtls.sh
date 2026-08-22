#!/bin/bash
#
# mTLS client certificate helper. Run inside the container:
#   docker compose exec proxy bash /root/.acme.sh/mtls.sh init
#   docker compose exec proxy bash /root/.acme.sh/mtls.sh issue iphone
#   docker compose exec proxy bash /root/.acme.sh/mtls.sh list
#
# Files live in /certs/.mtls - dot prefixed because NXCT_SERVICE_DELTEOUTDATEDCERTS
# iterates /certs/*/ and would otherwise delete them.
#

MTLS_DIR="${NXCT_SERVICE_MTLS_DIR:-/certs/.mtls}"
CA_CRT="${NXCT_SERVICE_MTLS_CA:-/certs/client-ca.pem}"
CA_KEY="$MTLS_DIR/ca-key.pem"
CA_SRL="$MTLS_DIR/ca.srl"
CA_DAYS=3650
CLIENT_DAYS=1825

die() { echo "$@" >&2; exit 3; }

# Sign a CSR with the CA
# $1 = csr, $2 = out cert, $3 = subject CN
mtls_sign() {
  openssl x509 -req -in "$1" -out "$2" -days "$CLIENT_DAYS" -sha256 \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial -CAserial "$CA_SRL" \
    -extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE\n") \
    2>/dev/null || die "ERROR: signing failed for $3"
}

# Create key + signed cert pair
# $1 = basename (without extension), $2 = CN
mtls_keypair() {
  local base="$1" cn="$2"
  openssl genrsa -out "$base-key.pem" 2048 2>/dev/null
  openssl req -new -key "$base-key.pem" -out "$base.csr" -subj "/CN=$cn" 2>/dev/null
  mtls_sign "$base.csr" "$base-cert.pem" "$cn"
  rm -f "$base.csr"
}

cmd_init() {
  [ -s "$CA_CRT" ] && die "ERROR: CA already exists at $CA_CRT (delete it to start over)"
  mkdir -p "$MTLS_DIR"
  chmod 700 "$MTLS_DIR"

  echo "Generating client CA..."
  openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
  chmod 600 "$CA_KEY"
  openssl req -new -x509 -key "$CA_KEY" -out "$CA_CRT" -days "$CA_DAYS" -sha256 \
    -subj "/CN=NginxCrypt Client CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null \
    || die "ERROR: could not create CA"

  # Cert for upstream_monitor.sh, whose loopback HTTPS probes would otherwise be
  # rejected at the handshake and reported as the domain being down.
  echo "Generating monitor client cert..."
  mtls_keypair "$MTLS_DIR/monitor" "nginxcrypt-monitor"

  echo
  echo "CA created: $CA_CRT"
  echo "Now set NXCT_SERVICE_MTLS=true and issue a cert per device:"
  echo "  mtls.sh issue <device-name>"
}

cmd_issue() {
  local name="$1" base p12pass
  [ -z "$name" ] && die "Usage: mtls.sh issue <device-name>"
  [ -s "$CA_CRT" ] || die "ERROR: no CA yet - run 'mtls.sh init' first"
  case "$name" in
    *[!a-zA-Z0-9._-]*) die "ERROR: device name may only contain a-z A-Z 0-9 . _ -" ;;
  esac
  base="$MTLS_DIR/client-$name"
  [ -s "$base-cert.pem" ] && die "ERROR: $name already issued ($base-cert.pem)"

  mtls_keypair "$base" "$name"
  p12pass=$(openssl rand -base64 12)
  # -legacy may be needed for pre-iOS 15 / older Windows; see docs
  openssl pkcs12 -export -out "$base.p12" \
    -inkey "$base-key.pem" -in "$base-cert.pem" -certfile "$CA_CRT" \
    -name "$name" -passout "pass:$p12pass" 2>/dev/null \
    || die "ERROR: could not build .p12 for $name"
  chmod 600 "$base.p12"

  echo
  echo "Issued: $base.p12"
  echo "Import password: $p12pass"
  echo "Valid until: $(openssl x509 -in "$base-cert.pem" -noout -enddate | cut -d= -f2)"
  echo
  echo "On the host the file is under .volumes/proxy/certs/.mtls/"
}

cmd_list() {
  [ -s "$CA_CRT" ] || die "ERROR: no CA yet - run 'mtls.sh init' first"
  echo "CA:      $(openssl x509 -in "$CA_CRT" -noout -enddate | cut -d= -f2)"
  local f cn
  for f in "$MTLS_DIR"/client-*-cert.pem "$MTLS_DIR"/monitor-cert.pem; do
    [ -s "$f" ] || continue
    cn=$(openssl x509 -in "$f" -noout -subject | sed 's/.*CN *= *//')
    printf "  %-24s expires %s\n" "$cn" "$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)"
  done
}

case "$1" in
  init)  cmd_init ;;
  issue) cmd_issue "$2" ;;
  list)  cmd_list ;;
  *)     echo "Usage: mtls.sh {init|issue <device-name>|list}" >&2; exit 1 ;;
esac
