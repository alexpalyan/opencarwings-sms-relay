#!/bin/sh
# mkca.sh — regenerate ca/roots.pem, the CA bundle embedded into the binary.
#
# The default OpenCARWINGS gateway is Cloudflare-fronted, and Cloudflare rotates
# its edge issuer between Google Trust Services and Let's Encrypt. Embedded modem
# firmware ships no system trust store, so the relay carries its own minimal set
# of roots. We bundle both issuer families (plus the GlobalSign cross-sign anchor)
# so an issuer rotation does not require a rebuild.
#
# Roots are fetched from their authoritative publishers and each is verified to be
# a self-signed CA before it is written. Re-run after a known root rotation:
#
#     sh tools/mkca.sh && git diff ca/roots.pem
#
# Requires: curl, openssl.
set -eu

OUT=ca/roots.pem
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# name|url   (Google Trust Services R1-R4, GlobalSign Root CA, ISRG X1/X2)
SPECS='
GTS Root R1|https://pki.goog/repo/certs/gtsr1.pem
GTS Root R2|https://pki.goog/repo/certs/gtsr2.pem
GTS Root R3|https://pki.goog/repo/certs/gtsr3.pem
GTS Root R4|https://pki.goog/repo/certs/gtsr4.pem
GlobalSign Root CA|https://secure.globalsign.com/cacert/root-r1.crt
ISRG Root X1|https://letsencrypt.org/certs/isrgrootx1.pem
ISRG Root X2|https://letsencrypt.org/certs/isrg-root-x2.pem
'

: > "$OUT.new"
printf '%s\n' "$SPECS" | while IFS='|' read -r name url; do
	[ -n "$name" ] || continue
	raw="$TMP/raw"
	curl -fsSL "$url" -o "$raw"
	# Normalise DER or PEM to PEM.
	if grep -q 'BEGIN CERTIFICATE' "$raw" 2>/dev/null; then
		cp "$raw" "$TMP/pem"
	else
		openssl x509 -inform DER -in "$raw" -out "$TMP/pem"
	fi
	# RFC2253 keeps the DN string identical across OpenSSL/LibreSSL versions, so the
	# committed bundle stays byte-reproducible (the CI drift-check depends on this).
	subj=$(openssl x509 -in "$TMP/pem" -noout -subject -nameopt RFC2253 | sed 's/^subject= *//')
	iss=$(openssl x509 -in "$TMP/pem" -noout -issuer -nameopt RFC2253 | sed 's/^issuer= *//')
	if [ "$subj" != "$iss" ]; then
		echo "mkca: $name is not self-signed (subject != issuer), refusing" >&2
		exit 1
	fi
	fp=$(openssl x509 -in "$TMP/pem" -noout -fingerprint -sha256 | sed 's/^.*=//')
	{
		echo "# $name"
		echo "# subject: $subj"
		echo "# sha256:  $fp"
		openssl x509 -in "$TMP/pem" -outform PEM
		echo
	} >> "$OUT.new"
	echo "  + $name" >&2
done

mv "$OUT.new" "$OUT"
n=$(grep -c 'BEGIN CERTIFICATE' "$OUT")
echo "mkca: wrote $OUT ($n certificates, $(wc -c < "$OUT") bytes)" >&2
