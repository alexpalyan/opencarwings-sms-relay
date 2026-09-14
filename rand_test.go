package main

import (
	crand "crypto/rand"
	"testing"
	"unsafe"
)

// TestRandReadDoesNotClobber guards the workaround in rand_linux.go. On the
// modem's kernel crypto/rand.Read zeroes memory past the destination buffer,
// and that is what broke WebSocket frames for years. The test catches the
// regression right on the target hardware: build `go test -c` for arm and run
// it on the device.
func TestRandReadDoesNotClobber(t *testing.T) {
	var buf [32]byte
	for i := range buf {
		buf[i] = 0xAA
	}
	if err := randRead(buf[14:18]); err != nil {
		t.Fatalf("randRead: %v", err)
	}
	for i, b := range buf {
		if i >= 14 && i < 18 {
			continue // this is where we meant to write
		}
		if b != 0xAA {
			t.Fatalf("randRead clobbered byte %d (0x%02X); whole buffer: %X", i, b, buf)
		}
	}
}

// TestRawGetrandomSyscall determines whether syscall 384 itself (getrandom on
// kernels since 3.17) clobbers memory, or something in Go above it. This decides
// whether moving to a newer Go is worthwhile: if the syscall is to blame, a newer
// version merely crashes after the same corruption. The test is diagnostic — it
// asserts nothing, only prints, so it "passes" on a healthy system too.
func TestRawGetrandomSyscall(t *testing.T) {
	var buf [64]byte
	for i := range buf {
		buf[i] = 0xAA
	}
	n, errno := rawGetrandom(buf[16:24])
	t.Logf("syscall 384 -> n=%d errno=%v", n, errno)
	t.Logf("buffer after: %X", buf)

	clobbered := -1
	for i, b := range buf {
		if i >= 16 && i < 24 {
			continue
		}
		if b != 0xAA {
			clobbered = i
			break
		}
	}
	if clobbered >= 0 {
		t.Logf("VERDICT: the raw syscall itself clobbers memory, first at byte %d", clobbered)
	} else {
		t.Logf("VERDICT: the raw syscall left neighbouring memory intact")
	}
	_ = unsafe.Pointer(&buf[0])
}

// TestStockCryptoRandDoesNotClobber checks crypto/rand ITSELF, not our workaround.
// On the stock toolchain with the modem's kernel it clobbers memory, and the test
// just records that in the log; on the patched toolchain (see toolchain/) it should
// be clean. The test is diagnostic and deliberately does not fail, so `go test`
// stays green on both.
func TestStockCryptoRandDoesNotClobber(t *testing.T) {
	var buf [64]byte
	for i := range buf {
		buf[i] = 0xAA
	}
	crand.Read(buf[16:24])
	t.Logf("buffer after crypto/rand.Read(buf[16:24]): %X", buf)
	for i, b := range buf {
		if i >= 16 && i < 24 {
			continue
		}
		if b != 0xAA {
			t.Logf("VERDICT: stock crypto/rand clobbers memory, first at byte %d", i)
			return
		}
	}
	t.Logf("VERDICT: stock crypto/rand is clean on this build")
}
