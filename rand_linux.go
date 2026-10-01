//go:build linux

package main

import (
	"crypto/rand"
	"io"
	"os"
	"sync"
)

// randRead is a source of randomness that does not clobber neighbouring memory.
//
// On this modem's kernel (a custom 3.4.110) crypto/rand.Read is treacherous: it
// returns err=nil and genuinely correct random bytes, but it ALSO zeroes memory
// past the destination buffer — on the stack and on the heap alike. The cause is
// syscall 384: that number only became getrandom(2) in kernel 3.17, and on this
// vendor ZTE kernel it is sys_get_flashtestinfo instead, which treats the pointer
// and length as its own arguments.
//
// The consequence was invisible and expensive. In writeFrame the call sat between
// writing the frame header and masking it, so it wiped hdr[0] and hdr[1]: instead
// of a Pong (0x8A 0x8C) the socket received a frame with opcode 0x0 (continuation)
// and no MASK bit. Servers reject such a frame — hence the 20-second disconnects
// from OpenCARWINGS, and the long-standing mysterious 1002 "continuation after
// final message frame" error from echo.websocket.org.
//
// /dev/urandom is verified clean: see TestRandReadDoesNotClobber.
var (
	urandomOnce sync.Once
	urandomFile *os.File
)

func randRead(b []byte) error {
	urandomOnce.Do(func() {
		urandomFile, _ = os.Open("/dev/urandom")
	})
	if urandomFile != nil {
		if _, err := io.ReadFull(urandomFile, b); err == nil {
			return nil
		}
	}
	// Better corrupted memory than predictable keys: if /dev/urandom is
	// unavailable, fall back to the standard source.
	_, err := rand.Read(b)
	return err
}
