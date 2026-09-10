//go:build linux

package main

import (
	"syscall"
	"testing"
	"unsafe"
)

func TestFdSetAndIsSet(t *testing.T) {
	var s syscall.FdSet
	fdZero(&s)

	bitsPerElem := int(unsafe.Sizeof(s.Bits[0])) * 8
	maxFd := len(s.Bits) * bitsPerElem

	testFDs := []int{0, 1, 31, 32, 63, 64, 100, 500, 1023}
	for _, fd := range testFDs {
		if fdIsSet(fd, &s) {
			t.Errorf("fdIsSet(%d) should be false initially", fd)
		}
		fdSet(fd, &s)
		if !fdIsSet(fd, &s) {
			t.Errorf("fdIsSet(%d) should be true after fdSet", fd)
		}
	}

	// Verify fdZero clears all bits
	fdZero(&s)
	for _, fd := range testFDs {
		if fdIsSet(fd, &s) {
			t.Errorf("fdIsSet(%d) should be false after fdZero", fd)
		}
	}

	// Verify boundary protection (should not panic)
	outOfBoundsFDs := []int{-1, -100, maxFd, maxFd + 1, 2048}
	for _, fd := range outOfBoundsFDs {
		fdSet(fd, &s)
		if fdIsSet(fd, &s) {
			t.Errorf("fdIsSet(%d) out of bounds should return false", fd)
		}
	}
}
