package main

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"
)

// embeddedRoots is a small, curated CA bundle compiled into the binary. Embedded
// modem firmware ships no /etc/ssl/certs, so without this the WebSocket client
// could not validate TLS to the OpenCARWINGS gateway at all. It carries the
// Google Trust Services and Let's Encrypt (ISRG) root families plus the GlobalSign
// cross-sign anchor, so the Cloudflare-fronted default endpoint keeps validating
// across an issuer rotation. Regenerate with tools/mkca.sh.
//
//go:embed ca/roots.pem
var embeddedRoots []byte

// rootPool builds the trust anchor set for TLS, composing three sources so they
// add up rather than shadow each other:
//
//	system roots (if the host has any) ∪ embeddedRoots ∪ the -ws-ca PEM (if given)
//
// On the modem SystemCertPool yields nothing, so the embedded bundle is the whole
// trust store; on a dev host it augments the system store. -ws-ca then extends
// trust further — for another endpoint, or as an escape hatch during a root
// rotation the embedded bundle has not caught up with yet.
func rootPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(embeddedRoots) {
		return nil, fmt.Errorf("embedded CA bundle is invalid (rebuild with tools/mkca.sh)")
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("-ws-ca %s: %w", caFile, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-ws-ca %s: no certificates found", caFile)
		}
	}
	return pool, nil
}
