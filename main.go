// sms-relay — On-device webhook relay for OpenCarWings → binary SMS via ZTE modem interface.
//
// Runs directly on the LTE modem (ZTE MF79U / ZX297520V3), eliminating the need for a host PC.
// The panel POSTs a JSON payload: {message, type, pdu, pdu_length}. The pre-built
// SMS-SUBMIT PDU is in the `pdu` field (recipient phone number encoded inside). We return HTTP 200
// immediately and send the PDU asynchronously via AT+CMGS over the atserver socket or raw /dev/rpm30 node.
//
// HTTP Layer — Raw net.Listener (WITHOUT net/http):
// The modem has ~6 MB of free RAM. The standard Go net/http runtime memory overhead triggers the kernel
// Linux Out-Of-Memory Killer (LMK). A lightweight HTTP/1.1 parser keeps memory usage minimal.
//
// Security:
// /hook is secured via a secret URL path component (/hook/<secret>). Listens on local interface only,
// keeping modem web UI on port 80 untouched. Exposed via secure tunnel (e.g. cloudflared).
//
// Logging:
// Logs to /cache/sms-relay-log/relay-YYYYMMDD.jsonl (ubifs partition, survives reboot).
//
// Cross-compilation for ZTE modem (ARMv7 32-bit / ARMv5 softfloat depending on target):
//
//	GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sms-relay .
//
// Usage on modem:
//
//	/cache/sms-relay -secret <TOKEN> [-listen 192.168.0.1:8787] [-report]
package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	dev      = flag.String("dev", "/dev/rpm30", "ZTE modem AT device node")
	listen   = flag.String("listen", "192.168.0.1:8787", "host:port binding (LAN only)")
	secret   = flag.String("secret", "", "URL secret path token: POST /hook/<secret> (required or SMS_RELAY_SECRET env var)")
	report   = flag.Bool("report", false, "Request +CDS delivery reports and log TP-ST status (holds rpm30 up to 90s — debug only)")
	cooldown = flag.Duration("cooldown", 90*time.Second, "Cooldown duration to mute duplicate PDU submissions")
	logDir   = flag.String("logdir", "/cache/sms-relay-log", "Directory for persistent JSON logs")
	debug    = flag.Bool("debug", false, "Verbose step-by-step markers + raw body dump in debug.log (contains full PDU with phone number!)")
	logURL   = flag.Bool("logurl", false, "Expose GET /log/<secret> via HTTP (log contains phone number fragment) — default off, direct file access recommended")
	selftest = flag.Int("selftest", 0, "Diagnostic mode: N cycles open->AT/AT+CSQ->close, display thread stats and exit (does NOT send SMS)")

	atMode   = flag.String("at", "auto", "AT transport mode: auto|atsrv|rpm30 (auto = atserver if running)")
	atSock   = flag.String("atsock", "/tmp/zte_socket/AT_SERVER_MSG", "Unix socket path for atserver")
	atBin    = flag.String("atbin", "/bin/atserver", "atserver binary path for watchdog")
	watchdog = flag.Duration("watchdog", 60*time.Second, "atserver watchdog check interval (0 = disable)")
	reqlog   = flag.Bool("reqlog", false, "Write request headers and timings to reqlog.jsonl (for duplicate request analysis; PDU content is NOT logged)")
)

var (
	modemMu  sync.Mutex // Serializes access to modem transport
	stateMu  sync.Mutex
	lastPDU  string
	lastSent time.Time

	failMu       sync.Mutex
	consecFails  int
	backoffUntil time.Time
)

// backoffFor calculates exponential backoff after 3 consecutive failures.
// Since the transport channel is shared with stock atserver, repeated hammering can break cellular stack.
// Starts at 5m, doubles up to a maximum cap of 2h.
func backoffFor(fails int) time.Duration {
	if fails < 3 {
		return 0
	}
	d := 5 * time.Minute
	for i := 3; i < fails; i++ {
		if d >= 2*time.Hour {
			break
		}
		d *= 2
	}
	if d > 2*time.Hour {
		d = 2 * time.Hour
	}
	return d
}

func main() {
	flag.Parse()
	if *secret == "" {
		*secret = os.Getenv("SMS_RELAY_SECRET")
	}

	if *selftest > 0 {
		runSelfTest(*selftest)
		return
	}
	if *secret == "" {
		fmt.Println("❌ -secret <TOKEN> or SMS_RELAY_SECRET environment variable is required (protects /hook endpoint)")
		os.Exit(2)
	}

	// Note on OOM score adjustment:
	// We intentionally do not lower oom_score_adj (e.g. -800). On ~55MB total system RAM,
	// under memory pressure the kernel would terminate stock firmware processes (atserver/zte_*)
	// instead of our non-critical relay — leaving the modem without cellular network connectivity.
	// A supervisor will restart this relay, whereas stock processes won't be recovered automatically.
	if err := os.MkdirAll(*logDir, 0755); err != nil {
		fmt.Printf("⚠️  logdir %s: %v\n", *logDir, err)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Printf("❌ listen %s: %v\n", *listen, err)
		os.Exit(1)
	}
	fmt.Printf("sms-relay running at http://%s  hook: POST /hook/<secret>\n", *listen)
	fmt.Printf("device %s  report(+CDS)=%v  cooldown=%s  logdir=%s\n", *dev, *report, *cooldown, *logDir)
	fmt.Printf("transport: at=%s → currently %q (atserver pid=%d, socket %s)\n",
		*atMode, pickTransport(), atServerPID(), *atSock)
	if *watchdog > 0 {
		fmt.Printf("atserver watchdog: checking every %s\n", *watchdog)
		go watchdogLoop()
	}
	var tempDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if maxDelay := 1 * time.Second; tempDelay > maxDelay {
				tempDelay = maxDelay
			}
			fmt.Printf("⚠️ accept error: %v; retrying in %v\n", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
		go serve(c)
	}
}

// ---------------------------------------------------------------------------
// Transport Diagnostics & Self-Test

// runSelfTest runs N cycles of open->AT->close on the device node WITHOUT sending SMS.
// Purpose: verify that the select-based transport does not leave OS threads in D-state.
// (On older blocking reads, each cycle permanently leaked a thread in zDrvRpMsg_Read).
func runSelfTest(n int) {
	fmt.Printf("selftest: %d cycles, transport=%q (SMS sending disabled)\n", n, pickTransport())
	if pickTransport() == "atsrv" {
		runSelfTestATSrv(n)
		return
	}
	fmt.Printf("  device node %s\n", *dev)
	fmt.Printf("  threads at start: %s, uninterruptible (D) state: %d\n", procThreads(), countDThreads())
	okCount := 0
	for i := 1; i <= n; i++ {
		p, err := openPort(*dev)
		if err != nil {
			fmt.Printf("  %2d: open: %v\n", i, err)
			continue
		}
		at := oneLine(p.cmd("AT", 3*time.Second))
		csq := oneLine(p.cmd("AT+CSQ", 3*time.Second))
		p.close()
		if strings.Contains(at, "OK") {
			okCount++
		}
		fmt.Printf("  %2d: AT=%-14q CSQ=%-28q threads=%s D=%d\n", i, at, csq, procThreads(), countDThreads())
	}
	d := countDThreads()
	fmt.Printf("selftest: %d/%d AT-OK, threads at end: %s, D-state: %d %s\n",
		okCount, n, procThreads(), d, ifStr(d == 0, "✅ no thread leak", "❌ THREAD LEAK DETECTED"))
}

// runSelfTestATSrv executes N requests over atserver Unix socket and checks if it survives.
// (Unread responses or rapid bursts can crash atserver).
func runSelfTestATSrv(n int) {
	pid0 := atServerPID()
	fmt.Printf("  socket %s, atserver pid=%d, gap between requests %s\n", *atSock, pid0, atSrvGap)
	if pid0 == 0 {
		fmt.Println("  ❌ atserver is not running — nothing to test")
		return
	}
	okCount := 0
	for i := 1; i <= n; i++ {
		if i > 1 {
			time.Sleep(atSrvGap)
		}
		at, err1 := atSrvCmd(*atSock, "AT", 5*time.Second)
		time.Sleep(atSrvGap)
		csq, err2 := atSrvCmd(*atSock, "AT+CSQ", 5*time.Second)
		pid := atServerPID()
		if err1 == nil && err2 == nil && strings.Contains(at, "OK") && strings.Contains(csq, "+CSQ") {
			okCount++
		}
		fmt.Printf("  %2d: AT=%-10q CSQ=%-24q atserver=%d\n", i, oneLine(at), oneLine(csq), pid)
		if pid == 0 {
			fmt.Printf("  ❌ atserver CRASHED on cycle %d — transport is unsafe\n", i)
			return
		}
	}
	pid := atServerPID()
	fmt.Printf("selftest: %d/%d clean, atserver pid=%d (was %d) %s\n", okCount, n, pid, pid0,
		ifStr(pid == pid0 && okCount == n, "✅ stable", "⚠️ discrepancies found"))
	dryRunCMGS()
}

// dryRunCMGS tests TWO-STAGE framing using AT+CMGW (write to memory) instead of AT+CMGS,
// ensuring no actual SMS is transmitted over cellular network.
// If framing is corrupted (e.g. extra CRLF at PDU end), modem returns "+CME ERROR: 6002".
// Correct framing yields "+CMGW: <index>", which we immediately delete.
func dryRunCMGS() {
	const testPDU = "0001000C9183902143658700000141" // SMSC=0, 1 character 'A', TPDU=14, Phone=+380912345678
	const testLen = 14
	fmt.Println("Dry run CMGS framing check (via CMGW, no SMS sent):")
	if _, err := atSrvCmd(*atSock, "AT+CMGF=0", 5*time.Second); err != nil {
		fmt.Printf("  ❌ AT+CMGF=0: %v\n", err)
		return
	}
	time.Sleep(atSrvGap)
	r, err := atSrvCmd(*atSock, fmt.Sprintf("AT+CMGW=%d>%s", testLen, testPDU), 15*time.Second)
	if err != nil {
		fmt.Printf("  ❌ CMGW: %v\n", err)
		return
	}
	if !strings.Contains(r, "+CMGW") {
		fmt.Printf("  ❌ framing corrupted: %s\n", oneLine(r))
		return
	}
	fmt.Printf("  ✅ framing correct: %s\n", oneLine(r))
	idx := ""
	if f := strings.Fields(strings.SplitN(oneLine(r), "+CMGW:", 2)[1]); len(f) > 0 {
		idx = f[0]
	}
	if idx == "" {
		fmt.Println("  ⚠️  could not parse record index — check memory: AT+CMGL=4")
		return
	}
	time.Sleep(atSrvGap)
	if d, err := atSrvCmd(*atSock, "AT+CMGD="+idx, 10*time.Second); err == nil && strings.Contains(d, "OK") {
		fmt.Printf("  🧹 test record %s deleted\n", idx)
	} else {
		fmt.Printf("  ⚠️  failed to delete record %s — remove manually: AT+CMGD=%s\n", idx, idx)
	}
}

func oneLine(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
}

func procThreads() string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "?"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "Threads:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "Threads:"))
		}
	}
	return "?"
}

// ---------------------------------------------------------------------------
// Lightweight HTTP/1.1 Engine (single request per connection, Connection: close)

type request struct {
	method, path string
	ctype        string
	body         []byte
	peer         string

	// Used for -reqlog diagnostic logging
	hdrs     []string
	clen     int       // Content-Length header value
	bodyGot  int       // Actual bytes read from body
	t0       time.Time // Connection start timestamp
	tHeaders time.Time // Headers parsed timestamp
	tBody    time.Time // Body read timestamp
}

func serve(c net.Conn) {
	defer c.Close()
	t0 := time.Now()
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)

	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	req := request{method: parts[0], path: parts[1], peer: c.RemoteAddr().String(), t0: t0}

	var clen int
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if h == "\r\n" || h == "\n" {
			break
		}
		if i := strings.IndexByte(h, ':'); i > 0 {
			k := strings.TrimSpace(h[:i])
			v := strings.TrimSpace(h[i+1:])
			if strings.EqualFold(k, "Content-Length") {
				clen, _ = strconv.Atoi(v)
			} else if strings.EqualFold(k, "Content-Type") {
				req.ctype = v
			}
			if *reqlog {
				switch strings.ToLower(k) {
				case "authorization", "cookie", "proxy-authorization":
					v = "<redacted>"
				}
				req.hdrs = append(req.hdrs, k+": "+v)
			}
		}
	}
	req.clen = clen
	req.tHeaders = time.Now()
	if clen > 0 {
		if clen > 1<<16 {
			clen = 1 << 16
		}
		req.body = make([]byte, clen)
		n, _ := io.ReadFull(br, req.body)
		req.bodyGot = n
	}
	req.tBody = time.Now()

	status, respBody := route(&req)
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, len(respBody), respBody)
	logRequest(&req, status)
}

// logRequest writes transport diagnostics (headers like CF-Ray, request timings, body completion status).
// PDU content and phone numbers are NOT logged here.
func logRequest(req *request, status string) {
	if !*reqlog {
		return
	}
	now := time.Now()
	rec := map[string]any{
		"ts":         req.t0.UTC().Format(time.RFC3339Nano),
		"method":     req.method,
		"path":       ifStr(matchSecretPath(req.path, "/hook/", *secret), "/hook/<secret>", req.path),
		"peer":       req.peer,
		"status":     status,
		"ctype":      req.ctype,
		"clen":       req.clen,
		"body_got":   req.bodyGot,
		"truncated":  req.bodyGot < req.clen,
		"ms_headers": float64(req.tHeaders.Sub(req.t0).Microseconds()) / 1000,
		"ms_body":    float64(req.tBody.Sub(req.tHeaders).Microseconds()) / 1000,
		"ms_total":   float64(now.Sub(req.t0).Microseconds()) / 1000,
		"hdrs":       req.hdrs,
	}
	appendJSONL(filepath.Join(*logDir, "reqlog.jsonl"), rec)
}

func matchSecretPath(path, prefix, sec string) bool {
	if sec == "" {
		return false
	}
	expected := prefix + sec
	if len(path) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(path), []byte(expected)) == 1
}

func route(req *request) (string, string) {
	switch {
	case req.path == "/health":
		if req.method != "GET" && req.method != "HEAD" {
			return "405 Method Not Allowed", "method not allowed\n"
		}
		return "200 OK", "ok\n"
	case matchSecretPath(req.path, "/hook/", *secret):
		if req.method != "POST" {
			return "405 Method Not Allowed", "method not allowed\n"
		}
		return handleHook(req), ""
	case *logURL && matchSecretPath(req.path, "/log/", *secret):
		if req.method != "GET" {
			return "405 Method Not Allowed", "method not allowed\n"
		}
		name := filepath.Join(*logDir, "relay-"+time.Now().UTC().Format("20060102")+".jsonl")
		if b, err := os.ReadFile(name); err == nil {
			return "200 OK", string(b)
		}
		return "404 Not Found", "no log for today\n"
	default:
		return "404 Not Found", ""
	}
}

// ---------------------------------------------------------------------------

type hookBody struct {
	Message   string `json:"message"`
	Type      any    `json:"type"` // panel sends integer type (e.g. 1); type `any` avoids parsing errors
	PDU       string `json:"pdu"`
	PDULength int    `json:"pdu_length"`
}

// handleHook always returns HTTP 200 (panel does not retry on non-200); processing runs in background.
func handleHook(req *request) string {
	ts := time.Now().UTC()
	result := "logged"
	var phone string
	var body hookBody

	if err := json.Unmarshal(req.body, &body); err != nil {
		result = "not-json"
		dbg(fmt.Sprintf("RAW ct=%q body=%q", req.ctype, string(req.body)))
		logNoPDUBody(req, "not-json")
	} else if body.PDU == "" {
		result = "no-pdu"
		dbg(fmt.Sprintf("RAW ct=%q body=%q", req.ctype, string(req.body)))
		logNoPDUBody(req, "no-pdu")
	} else if info, derr := decodeSubmitPDU(body.PDU); derr != nil {
		result = "bad-pdu"
	} else {
		phone = info.phone
		tpduLen := body.PDULength
		if tpduLen == 0 {
			tpduLen = info.atLength
		}
		stateMu.Lock()
		if *reqlog {
			logPDUDiff(body.PDU, lastPDU, info, time.Since(lastSent))
		}
		dup := body.PDU == lastPDU && time.Since(lastSent) < *cooldown
		if dup {
			result = "cooldown-dup"
		} else {
			lastPDU = body.PDU
			lastSent = time.Now()
			result = "queued"
		}
		stateMu.Unlock()
		if !dup {
			rec := map[string]any{
				"ts": ts.Format(time.RFC3339), "peer": req.peer,
				"phone": redact(phone), "dcs": info.dcs, "tpdu_len": tpduLen, "type": body.Type,
			}
			go sendWorker(body.PDU, tpduLen, rec)
		}
	}

	logJSON(map[string]any{
		"ts": ts.Format(time.RFC3339), "method": req.method, "peer": req.peer,
		"len": len(req.body), "result": result, "phone": redactOrNil(phone),
	})
	fmt.Printf("%s %s peer=%s -> %s%s\n", ts.Format("15:04:05"), req.method, req.peer, result,
		ifStr(phone != "", " → "+redact(phone), ""))
	return "200 OK"
}

func sendWorker(pduHex string, tpduLen int, base map[string]any) {
	emit := func(res, line string) {
		rec := map[string]any{}
		for k, v := range base {
			rec[k] = v
		}
		rec["result"] = res
		rec["at"] = line
		logJSON(rec)
	}

	failMu.Lock()
	until, fails := backoffUntil, consecFails
	failMu.Unlock()
	if time.Now().Before(until) {
		left := time.Until(until).Truncate(time.Second)
		msg := fmt.Sprintf("backoff for another %s (%d consecutive failures)", left, fails)
		fmt.Printf("    ⏸  rpm30: %s — skipping transport execution\n", msg)
		emit("backoff", msg)
		return
	}

	tr := pickTransport()
	modemMu.Lock()
	var ok bool
	var info string
	if tr == "atsrv" {
		ok, info = sendPDUviaATSrv(*atSock, pduHex, tpduLen)
	} else {
		ok, info = sendPDU(*dev, pduHex, tpduLen, *report)
	}
	modemMu.Unlock()

	line := strings.ReplaceAll(strings.ReplaceAll(info, "\r", " "), "\n", " | ")
	mark, res := "❌", "send-failed"
	if ok {
		mark, res = "✅", "sent"
	}
	fmt.Printf("    %s %s: %s\n", mark, tr, line)
	base["transport"] = tr
	emit(res, line)

	failMu.Lock()
	if ok {
		consecFails, backoffUntil = 0, time.Time{}
	} else {
		consecFails++
		if d := backoffFor(consecFails); d > 0 {
			backoffUntil = time.Now().Add(d)
			fmt.Printf("    ⏸  rpm30: %d consecutive failures -> cooling down for %s\n", consecFails, d)
		}
	}
	failMu.Unlock()
}

// logNoPDUBody stores request payload when `pdu` is missing (for telemetry debugging).
// Payload is written locally to logDir on modem without phone numbers.
func logNoPDUBody(req *request, why string) {
	if !*reqlog {
		return
	}
	b := string(req.body)
	if len(b) > 512 {
		b = b[:512] + "…"
	}
	appendJSONL(filepath.Join(*logDir, "reqlog.jsonl"), map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"kind":  "no-pdu-body",
		"why":   why,
		"ctype": req.ctype,
		"peer":  req.peer,
		"body":  b,
	})
}

// logPDUDiff inspects changes between consecutive incoming PDUs.
// If the difference is only TP-MR, it represents a re-generated message from panel rather than an HTTP retry.
func logPDUDiff(cur, prev string, info pduInfo, since time.Duration) {
	rec := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"kind":     "pdu-diff",
		"tp_mr":    info.mr,
		"pdu_len":  len(cur) / 2,
		"dcs":      info.dcs,
		"since_ms": since.Milliseconds(),
	}
	switch {
	case prev == "":
		rec["vs_prev"] = "first PDU since start"
	case cur == prev:
		rec["vs_prev"] = "IDENTICAL to previous (likely HTTP retry)"
	default:
		diff, first := 0, -1
		n := len(cur)
		if len(prev) < n {
			n = len(prev)
		}
		for i := 0; i < n; i++ {
			if cur[i] != prev[i] {
				diff++
				if first < 0 {
					first = i
				}
			}
		}
		diff += absInt(len(cur) - len(prev))
		rec["vs_prev"] = "different"
		rec["diff_nibbles"] = diff
		rec["first_diff_at"] = first
		// TP-MR is right after SMSC + first octet. If diff is only there, it is a message re-generation.
		rec["only_tp_mr"] = diff <= 2 && first >= 0
	}
	appendJSONL(filepath.Join(*logDir, "reqlog.jsonl"), rec)
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// ---------------------------------------------------------------------------
// PDU Parsing

type pduInfo struct {
	phone    string
	dcs      int
	atLength int
	mr       int // TP-MR message reference counter
}

func decodeSubmitPDU(pduHex string) (info pduInfo, err error) {
	p, err := hex.DecodeString(strings.TrimSpace(pduHex))
	if err != nil {
		return
	}
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("truncated or invalid PDU")
		}
	}()
	i := int(p[0]) + 1 // skip SMSC header
	i += 2             // first octet + TP-MR
	daLen := int(p[i])
	i += 2 // addr length + TON/NPI
	nb := (daLen + 1) / 2
	var sb strings.Builder
	for _, b := range p[i : i+nb] {
		sb.WriteString(fmt.Sprintf("%X%X", b&0x0F, b>>4))
	}
	digits := sb.String()
	if len(digits) > daLen {
		digits = digits[:daLen]
	}
	i += nb
	info = pduInfo{
		phone:    digits,
		dcs:      int(p[i+1]),
		atLength: len(p) - 1 - int(p[0]),
		mr:       int(p[int(p[0])+2]),
	}
	return
}

// ---------------------------------------------------------------------------
// Transport via /bin/atserver (Primary)
//
// Why preferred over raw /dev/rpm30: atserver is the SINGLE owner of /dev/rpm30,
// preventing response collision with background polling (+CESQ).
// It also handles two-stage CMGS framing internally: text containing "+CMGS=" and ">"
// is automatically split, first part sent, waits for ">", sleeps 100ms, sends second part + Ctrl-Z.
//
// Protocol Constraints:
//   - Request MUST be EXACTLY atSrvReqSize (0x208) bytes (recv with MSG_WAITALL).
//   - Response MUST be read FULLY (atSrvRespSize = 0x2808 bytes), otherwise atserver catches SIGPIPE and CRASHES.
//   - Rapid connection bursts are not supported -> atSrvGap (300ms) required between requests.
//   - atserver lacks auto-restart -> monitored by watchdog loop.
const (
	atSrvReqSize  = 0x208  // recv(sock, buf, 0x208, MSG_WAITALL)
	atSrvRespSize = 0x2808 // send(sock, buf, 0x2808, ...)
	atSrvGap      = 300 * time.Millisecond
	atSrvTextMax  = atSrvReqSize - 8
)

// isATSrvCMGS checks if request triggers two-stage framing in atserver.
func isATSrvCMGS(text string) bool {
	up := strings.ToUpper(text)
	return (strings.Contains(up, "+CMGS=") || strings.Contains(up, "+CMGW=")) &&
		strings.Contains(text, ">")
}

func atSrvFrame(cmd string, timeout time.Duration) ([]byte, error) {
	text := strings.TrimRight(cmd, "\r\n")
	// Note: For two-stage CMGS/CMGW, CRLF must NOT be appended: atserver appends "\r\n"
	// to the part before ">" and Ctrl-Z to the part after.
	// Extra CRLF at end of PDU causes modem error: "+CME ERROR: 6002".
	if !isATSrvCMGS(text) {
		text += "\r\n"
	}
	if len(text) > atSrvTextMax {
		return nil, fmt.Errorf("AT string length %d > max %d", len(text), atSrvTextMax)
	}
	buf := make([]byte, atSrvReqSize) // fixed size buffer padded with zeros
	binary.LittleEndian.PutUint16(buf[0:], uint16(len(text)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(timeout/time.Millisecond))
	copy(buf[8:], text)
	return buf, nil
}

func atSrvCmd(sock, cmd string, timeout time.Duration) (string, error) {
	req, err := atSrvFrame(cmd, timeout)
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	conn.SetReadDeadline(time.Now().Add(timeout + 10*time.Second))
	resp := make([]byte, atSrvRespSize)
	// io.ReadFull ensures response buffer is completely drained to avoid crashing atserver with SIGPIPE.
	n, err := io.ReadFull(conn, resp)
	if n < 8 {
		return "", fmt.Errorf("short response (%d bytes): %v", n, err)
	}
	ln := int(binary.LittleEndian.Uint16(resp[0:]))
	if ln > n-8 {
		ln = n - 8
	}
	return string(resp[8 : 8+ln]), nil
}

// sendPDUviaATSrv: AT+CMEE=1 -> AT+CMGF=0 -> single request "AT+CMGS=<len>><PDU>".
// Note: +CDS delivery reports cannot be captured via atserver socket (URCs go to atserver's own channel).
func sendPDUviaATSrv(sock, pduHex string, tpduLen int) (bool, string) {
	if _, err := atSrvCmd(sock, "AT+CMEE=1", 5*time.Second); err != nil {
		return false, "atsrv AT+CMEE=1: " + err.Error()
	}
	time.Sleep(atSrvGap)

	r, err := atSrvCmd(sock, "AT+CMGF=0", 5*time.Second)
	if err != nil {
		return false, "atsrv AT+CMGF=0: " + err.Error()
	}
	if !strings.Contains(r, "OK") {
		return false, "AT+CMGF=0 without OK: " + oneLine(r)
	}
	time.Sleep(atSrvGap)

	// '>' acts as stage separator FOR atserver.
	r, err = atSrvCmd(sock, fmt.Sprintf("AT+CMGS=%d>%s", tpduLen, strings.ToUpper(pduHex)), 30*time.Second)
	if err != nil {
		return false, "atsrv AT+CMGS: " + err.Error()
	}
	return strings.Contains(r, "+CMGS"), oneLine(r)
}

// ---------------------------------------------------------------------------
// atserver Watchdog

// atServerPID scans /proc to locate running /bin/atserver without touching the Unix socket.
func atServerPID() int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(b) == 0 {
			continue
		}
		if strings.HasPrefix(string(cstr(b)), *atBin) {
			return pid
		}
	}
	return 0
}

func cstr(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// startATServer launches atserver detached via /bin/sh so it re-parents to init (PID 1).
func startATServer() error {
	return exec.Command("/bin/sh", "-c", "("+*atBin+" >/dev/null 2>&1 &)").Run()
}

func watchdogLoop() {
	for {
		time.Sleep(*watchdog)
		if atServerPID() != 0 {
			continue
		}
		fmt.Printf("%s ⚠️  atserver process disappeared — restarting (pppd depends on it)\n",
			time.Now().Format("15:04:05"))
		if err := startATServer(); err != nil {
			fmt.Printf("    ❌ start atserver failed: %v\n", err)
			logJSON(map[string]any{
				"ts":     time.Now().UTC().Format(time.RFC3339),
				"result": "atserver-restart-failed",
				"at":     err.Error(),
			})
			continue
		}
		time.Sleep(4 * time.Second)
		pid := atServerPID()
		fmt.Printf("    %s atserver pid=%d\n", ifStr(pid != 0, "✅", "❌"), pid)
		logJSON(map[string]any{
			"ts":     time.Now().UTC().Format(time.RFC3339),
			"result": ifStr(pid != 0, "atserver-restarted", "atserver-restart-failed"),
			"at":     fmt.Sprintf("pid=%d", pid),
		})
	}
}

func pickTransport() string {
	switch *atMode {
	case "atsrv":
		return "atsrv"
	case "rpm30":
		return "rpm30"
	}
	if *report {
		return "rpm30"
	}
	if atServerPID() != 0 {
		return "atsrv"
	}
	return "rpm30"
}

// ---------------------------------------------------------------------------
// Helpers & Diagnostics

func dbg(step string) {
	if !*debug {
		return
	}
	name := filepath.Join(*logDir, "debug.log")
	if f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		fmt.Fprintf(f, "%s %s\n", time.Now().Format("15:04:05.000"), step)
		f.Close()
	}
}

func logJSON(rec map[string]any) {
	appendJSONL(filepath.Join(*logDir, "relay-"+time.Now().UTC().Format("20060102")+".jsonl"), rec)
}

func appendJSONL(name string, rec map[string]any) {
	b, _ := json.Marshal(rec)
	if f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		f.Write(append(b, '\n'))
		f.Close()
	}
}

func redact(s string) string {
	if len(s) <= 6 {
		return "…"
	}
	return s[:4] + "…" + s[len(s)-2:]
}

func redactOrNil(s string) any {
	if s == "" {
		return nil
	}
	return redact(s)
}

func ifStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
