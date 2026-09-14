// mkoverlay prepares a -overlay for building with a patched Go toolchain.
//
// Why. The modem's kernel (Linux 3.4.110) answers syscall 384 differently from
// what Go expects. Since kernel 3.17 that number is getrandom(2), but this is a
// custom ZTE kernel where 384 is the vendor call sys_get_flashtestinfo: it writes
// 32 zero bytes at the passed pointer and returns EFAULT. Because of that
// crypto/rand either silently corrupts neighbouring memory (Go 1.23) or aborts the
// program (Go >= 1.24). Separately, Go >= 1.26 reserves 32 MiB of BSS for the FIPS
// DRBG, and with a CommitLimit of 27 MB the kernel simply refuses the exec.
//
// A fork of Go is not needed: `go build -overlay` substitutes files for the
// duration of the build, including inside GOROOT. This program makes copies of two
// standard-library files with the required edits and prints overlay.json.
//
// The edits are deliberately anchored to exact text fragments: if upstream changes
// them, the build fails here with a clear error instead of silently losing the patch.
//
// Usage:
//
//	go run ./toolchain/mkoverlay -out /tmp/ovl
//	GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 \
//	  go build -overlay=/tmp/ovl/overlay.json -o sms-relay .
//
// To verify on the device: build TestStockCryptoRandDoesNotClobber for arm
// (`go test -c`) and run it there — it reports whether stock crypto/rand is clean.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var outDir = flag.String("out", "", "directory for the patched files and overlay.json (required)")

// edit is a single text replacement anchored to a unique fragment.
type edit struct {
	old, new string
}

type target struct {
	rel   string // path relative to GOROOT/src
	edits []edit
}

var targets = []target{
	{
		rel: "crypto/internal/sysrand/rand_getrandom.go",
		edits: []edit{
			{
				old: "import (\n\t\"errors\"\n\t\"internal/syscall/unix\"\n\t\"math\"\n\t\"runtime\"\n\t\"syscall\"\n)",
				new: "import (\n\t\"errors\"\n\t\"internal/syscall/unix\"\n\t\"math\"\n\t\"runtime\"\n\t\"sync\"\n\t\"sync/atomic\"\n\t\"syscall\"\n)",
			},
			{
				old: "func read(b []byte) error {",
				new: `// getrandomUnavailable records that syscall 384 here is not a working
// getrandom(2). On vendor kernels older than 3.17 this number is not getrandom:
// on this custom ZTE kernel (Linux 3.4.110) it is sys_get_flashtestinfo, which
// writes 32 zero bytes at the passed pointer and only then reports EFAULT, i.e.
// it silently corrupts what lies past the caller's buffer. We probe once, into
// our own oversized buffer, so that damage cannot reach anyone else's data.
var (
	getrandomUnavailable atomic.Bool
	getrandomProbe       sync.Once
)

func probeGetRandom() {
	var scratch [128]byte
	if _, err := unix.GetRandom(scratch[:8], 0); err != nil {
		getrandomUnavailable.Store(true)
	}
}

func read(b []byte) error {
	getrandomProbe.Do(probeGetRandom)
	if getrandomUnavailable.Load() {
		return urandomRead(b)
	}
`,
			},
			{
				old: "\t\tif errors.Is(err, syscall.ENOSYS) {",
				new: "\t\tif errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EFAULT) {\n\t\t\tgetrandomUnavailable.Store(true)",
			},
		},
	},
	{
		rel: "crypto/internal/entropy/v1.0.0/entropy.go",
		edits: []edit{
			{
				old: "type ScratchBuffer [1 << 25]byte",
				new: "type ScratchBuffer [1 << 20]byte // 32 MiB of BSS prevents exec when CommitLimit is 27 MB",
			},
		},
	},
}

func main() {
	flag.Parse()
	if *outDir == "" {
		fmt.Fprintln(os.Stderr, "mkoverlay: -out is required")
		os.Exit(2)
	}
	goroot, err := goEnv("GOROOT")
	if err != nil {
		die("could not determine GOROOT: %v", err)
	}
	version, _ := goEnv("GOVERSION")
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		die("%v", err)
	}

	replace := map[string]string{}
	for _, t := range targets {
		src := filepath.Join(goroot, "src", t.rel)
		b, err := os.ReadFile(src)
		if err != nil {
			die("%s: %v", t.rel, err)
		}
		s := string(b)
		for i, e := range t.edits {
			if strings.Count(s, e.old) != 1 {
				die("%s: fragment #%d not found exactly once — upstream changed the code,\n"+
					"the patch needs review (toolchain %s)", t.rel, i+1, version)
			}
			s = strings.Replace(s, e.old, e.new, 1)
		}
		dst := filepath.Join(*outDir, filepath.Base(t.rel))
		if err := os.WriteFile(dst, []byte(s), 0o644); err != nil {
			die("%v", err)
		}
		replace[src] = dst
		fmt.Fprintf(os.Stderr, "patched %s (%d edits)\n", t.rel, len(t.edits))
	}

	path := filepath.Join(*outDir, "overlay.json")
	f, err := os.Create(path)
	if err != nil {
		die("%v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", " ")
	if err := enc.Encode(map[string]any{"Replace": replace}); err != nil {
		die("%v", err)
	}
	fmt.Fprintf(os.Stderr, "toolchain: %s\n", version)
	fmt.Println(path)
}

func goEnv(name string) (string, error) {
	out, err := exec.Command("go", "env", name).Output()
	return strings.TrimSpace(string(out)), err
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "mkoverlay: "+format+"\n", a...)
	os.Exit(1)
}
