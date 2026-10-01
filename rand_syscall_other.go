//go:build !(linux && arm)

package main

import "syscall"

// rawGetrandom is a stub: probing syscall 384 directly only makes sense on the modem's ARM kernel.
func rawGetrandom(b []byte) (int, syscall.Errno) { return 0, syscall.ENOSYS }
