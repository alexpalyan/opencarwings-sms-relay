//go:build !linux

package main

import "crypto/rand"

// randRead — on other systems crypto/rand behaves fine; the workaround is
// needed only for the modem's old kernel, see rand_linux.go.
func randRead(b []byte) error {
	_, err := rand.Read(b)
	return err
}
