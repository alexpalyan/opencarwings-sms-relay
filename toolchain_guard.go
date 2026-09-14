//go:build go1.24 && !patchedstdlib

package main

// This file exists solely to make the build fail loudly on a toolchain that
// produces a binary unusable on the target hardware. Both defects live in the
// Go + modem-kernel combination, and both are invisible at build time: the binary
// links, but dies on the device.
//
//	Go >= 1.26  crypto/internal/fips140/drbg.memory places a fixed 32 MiB in BSS.
//	            CommitLimit here is ~27 MB, so the kernel refuses the exec and kills
//	            the process before main() — no output, no core, nothing to debug.
//	            GOFIPS140=off does not remove this.
//
//	Go >= 1.24  crashes on the first read of random bytes. crypto/internal/sysrand
//	            has a fallback via /dev/urandom, but only enables it on ENOSYS,
//	            while this custom ZTE kernel (3.4.110) answers syscall 384 with
//	            EFAULT — there 384 is the vendor call sys_get_flashtestinfo, not
//	            getrandom(2) (which the number only became in kernel 3.17). For a
//	            TLS client that is every connection.
//
// Note separately that **Go 1.23 is not healthy either** — it is merely silent.
// The syscall writes 32 zero bytes past the destination buffer and returns EFAULT;
// Go 1.23 catches that error, falls back to /dev/urandom, and hands the caller
// err=nil plus correct random bytes. So the program sees success while memory a
// little further on has already been zeroed — which is exactly why this went
// unnoticed for years (here it clobbered a WebSocket frame header). Our code
// sidesteps it in rand_linux.go, but the defect in the standard library remains.
//
// Standard build (workaround in our code, standard library as-is):
//
//	GOTOOLCHAIN=go1.23.12 GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 \
//	  go build -trimpath -ldflags "-s -w" -o sms-relay .
//
// Build with a patched standard library removes both defects in Go itself and
// allows a supported version. The patchedstdlib tag disables this check, and may
// be set ONLY together with -overlay, otherwise you get a binary that will not run:
//
//	go run ./toolchain/mkoverlay -out /tmp/ovl
//	GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 \
//	  go build -overlay=/tmp/ovl/overlay.json -tags patchedstdlib \
//	  -trimpath -ldflags "-s -w" -o sms-relay .
//
// To verify on the device: build TestStockCryptoRandDoesNotClobber for arm
// (`go test -c`) and run it there — it reports whether stock crypto/rand is clean.
func init() {
	buildWithGo1_23_x__orPatchTheStdlibAndPassTagPatchedstdlib__seeToolchainGuardGo()
}
