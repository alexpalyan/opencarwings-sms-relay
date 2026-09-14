//go:build linux && arm

package main

import (
	"syscall"
	"unsafe"
)

// rawGetrandom calls syscall 384 directly. Since kernel 3.17 that is getrandom(2);
// on this custom ZTE kernel (3.4.110) it is the vendor call sys_get_flashtestinfo,
// and the tests probe how it behaves.
func rawGetrandom(b []byte) (int, syscall.Errno) {
	r, _, errno := syscall.Syscall(384, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	return int(r), errno
}
