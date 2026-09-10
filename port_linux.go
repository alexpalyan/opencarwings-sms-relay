//go:build linux

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// atPort handles raw /dev/rpm30 file descriptor. Reads MUST use select(2) with timeout.
//
// ⚠️ Driver Note: zx29_rpmsg driver IGNORES O_NONBLOCK:
// Raw syscall.Read blocks indefinitely in zDrvRpMsg_Read until baseband transmits data; EAGAIN is NEVER returned.
// Go runtime assigns a dedicated OS thread to blocking reads, and close(fd) cannot interrupt it,
// leaving threads stuck in uninterruptible sleep (D) state forever.
// Since rpm30 is SHARED with atserver, leaked reader threads steal responses from baseband and trigger cellular dropouts.
// The driver implements zx29_rpmsg_poll, so select(2) correctly signals readability and prevents thread exhaustion.
type atPort struct {
	fd      int
	mu      sync.Mutex
	buf     []byte
	stopped bool
	done    chan struct{}
}

const readTick = 200 * time.Millisecond

func fdZero(s *syscall.FdSet) {
	for i := range s.Bits {
		s.Bits[i] = 0
	}
}

func fdSet(fd int, s *syscall.FdSet) {
	bitsPerElem := int(unsafe.Sizeof(s.Bits[0])) * 8
	maxFd := len(s.Bits) * bitsPerElem
	if fd < 0 || fd >= maxFd {
		return
	}
	idx := fd / bitsPerElem
	offset := uint(fd % bitsPerElem)
	s.Bits[idx] |= 1 << offset
}

func fdIsSet(fd int, s *syscall.FdSet) bool {
	bitsPerElem := int(unsafe.Sizeof(s.Bits[0])) * 8
	maxFd := len(s.Bits) * bitsPerElem
	if fd < 0 || fd >= maxFd {
		return false
	}
	idx := fd / bitsPerElem
	offset := uint(fd % bitsPerElem)
	return (s.Bits[idx] & (1 << offset)) != 0
}

func openPort(devPath string) (*atPort, error) {
	fd, err := syscall.Open(devPath, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	p := &atPort{fd: fd, done: make(chan struct{})}
	go p.reader()
	return p, nil
}

func (p *atPort) reader() {
	defer close(p.done)
	b := make([]byte, 1024)
	for {
		p.mu.Lock()
		st := p.stopped
		p.mu.Unlock()
		if st {
			return
		}
		var rfds syscall.FdSet
		fdZero(&rfds)
		fdSet(p.fd, &rfds)
		tv := syscall.NsecToTimeval(readTick.Nanoseconds())
		n, err := syscall.Select(p.fd+1, &rfds, nil, nil, &tv)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}
		if n == 0 || !fdIsSet(p.fd, &rfds) {
			continue
		}
		nr, err := syscall.Read(p.fd, b)
		if nr > 0 {
			p.mu.Lock()
			p.buf = append(p.buf, b[:nr]...)
			p.mu.Unlock()
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || nr == 0 {
			continue
		}
		return
	}
}

func (p *atPort) drain()         { p.mu.Lock(); p.buf = nil; p.mu.Unlock() }
func (p *atPort) write(s string) { syscall.Write(p.fd, []byte(s)) }

// close waits for reader goroutine termination before closing fd to prevent race conditions on reused fds.
func (p *atPort) close() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		fmt.Println("    ⚠️  rpm30: reader goroutine did not terminate within 2s, leaving fd open")
		return
	}
	syscall.Close(p.fd)
}

func (p *atPort) waitFor(tokens []string, wait time.Duration) string {
	end := time.Now().Add(wait)
	for time.Now().Before(end) {
		p.mu.Lock()
		cur := string(p.buf)
		p.mu.Unlock()
		for _, t := range tokens {
			if strings.Contains(cur, t) {
				return cur
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.mu.Lock()
	cur := string(p.buf)
	p.mu.Unlock()
	return cur
}

func (p *atPort) cmd(s string, wait time.Duration) string {
	p.drain()
	p.write(s + "\r")
	return strings.TrimSpace(p.waitFor([]string{"OK", "ERROR"}, wait))
}

// sendPDU: AT+CMGF=0 -> (report: TP-SRR + CNMI) -> AT+CMGS -> '>' -> PDU+Ctrl-Z -> +CMGS/ERROR -> +CDS.
func sendPDU(devPath, pduHex string, tpduLen int, report bool) (bool, string) {
	dbg("open")
	p, err := openPort(devPath)
	if err != nil {
		return false, "open " + devPath + ": " + err.Error()
	}
	defer p.close()

	dbg("cmee")
	p.cmd("AT+CMEE=1", 3*time.Second)
	dbg("cmgf")
	if !strings.Contains(p.cmd("AT+CMGF=0", 3*time.Second), "OK") {
		return false, "AT+CMGF=0 missing OK"
	}
	if report {
		if raw, e := hex.DecodeString(pduHex); e == nil && len(raw) > 1 && 1+int(raw[0]) < len(raw) {
			raw[1+int(raw[0])] |= 0x20 // TP-SRR
			pduHex = hex.EncodeToString(raw)
		}
		dbg("cnmi")
		p.cmd("AT+CNMI=2,1,0,1,0", 3*time.Second)
	}

	dbg("cmgs")
	p.drain()
	p.write(fmt.Sprintf("AT+CMGS=%d\r", tpduLen))
	if !strings.Contains(p.waitFor([]string{">"}, 3*time.Second), ">") {
		return false, "prompt '>' not received"
	}
	dbg("prompt-ok")
	p.drain()
	p.write(strings.ToUpper(pduHex) + "\x1a")
	dbg("pdu-written")
	resp := strings.TrimSpace(p.waitFor([]string{"+CMGS", "ERROR", "+CMS"}, 20*time.Second))
	dbg("cmgs-resp:" + strings.ReplaceAll(strings.ReplaceAll(resp, "\r", " "), "\n", " "))
	ok := strings.Contains(resp, "+CMGS")
	if ok && report {
		p.drain()
		cds := strings.TrimSpace(p.waitFor([]string{"+CDS"}, 90*time.Second))
		if cds == "" {
			resp += " | (+CDS not received)"
		} else {
			resp += " | " + cds
			if v := decodeCDS(cds); v != "" {
				resp += " | " + v
			}
		}
	}
	return ok, resp
}

func decodeCDS(line string) string {
	var best []byte
	for _, tok := range strings.Fields(line) {
		if len(tok) == 0 || len(tok)%2 != 0 {
			continue
		}
		if b, err := hex.DecodeString(tok); err == nil && len(b) > len(best) {
			best = b
		}
	}
	if best == nil {
		return ""
	}
	defer func() { recover() }()
	p := best
	i := 1 + int(p[0])
	i += 2
	raLen := int(p[i])
	i += 1 + 1 + (raLen+1)/2
	i += 7 + 7
	if i >= len(p) {
		return ""
	}
	switch st := p[i]; {
	case st == 0x00:
		return "TP-ST=0x00 DELIVERED"
	case st < 0x20:
		return fmt.Sprintf("TP-ST=0x%02X IN TRANSIT", st)
	default:
		return fmt.Sprintf("TP-ST=0x%02X NOT DELIVERED", st)
	}
}

// countDThreads counts process threads stuck in uninterruptible sleep (D) state.
func countDThreads() int {
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range ents {
		b, err := os.ReadFile("/proc/self/task/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		st := string(b)
		i := strings.LastIndex(st, ")") // comm field inside parens may contain spaces
		if i < 0 {
			continue
		}
		if f := strings.Fields(st[i+1:]); len(f) > 0 && f[0] == "D" {
			n++
		}
	}
	return n
}
