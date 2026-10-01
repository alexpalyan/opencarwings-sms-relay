// WebSocket frontend for the public OpenCARWINGS SMS gateway protocol.
//
// Unlike -mode http, this dials OUT to the panel and holds the connection open, so the
// modem needs no inbound path at all: no port forwarding, no tunnel, and carrier-grade
// NAT on the cellular side stops mattering. That makes the modem a self-contained
// gateway — the reason this mode exists.
//
// Wire protocol (interoperable with developerfromjokela/opencarwings-sms):
//
//	wss://<host>/ws/smsgateway/?device_id=<16 hex chars>
//
// Server -> client frames are BINARY and encrypted with a pre-shared key:
//
//	IV (16 bytes) || AES-128-CBC-PKCS#7( JSON )
//
// Decrypted payloads:
//
//	{"type":"connect"}
//	{"type":"pdu","pdu":"<hex>","length":<int|null>}
//	{"type":"sms","sms":"<text>","phone":"<msisdn>"}
//
// The client never sends application data — only WebSocket ping/pong keepalives.
// Note the encryption carries no MAC and no replay protection; it is defence in depth
// behind TLS, not a substitute for it.
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// wsGUID is the fixed handshake salt from RFC 6455 section 1.3.
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// wsMaxPayload caps how much a single message may allocate. The modem has a few MB
	// of headroom, so a hostile or confused server must not be able to balloon us.
	wsMaxPayload  = 64 << 10
	wsHandshakeTO = 20 * time.Second
	wsDialTO      = 15 * time.Second
)

// RFC 6455 opcodes.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// ---------------------------------------------------------------------------
// Device identity

// wsIdentity is generated once and then pasted into the OpenCARWINGS panel to pair
// this gateway. It is persisted next to the logs so a restart keeps the same pairing.
type wsIdentity struct {
	DeviceID string `json:"device_id"`
	Key      string `json:"encryption_key"` // AES-128 key, hex
}

func wsIdentityPath() string {
	if *wsIDFile != "" {
		return *wsIDFile
	}
	return filepath.Join(*logDir, "ws-identity.json")
}

// loadWSIdentity reads the identity file, creating a fresh random one on first run.
func loadWSIdentity(path string) (wsIdentity, []byte, error) {
	var id wsIdentity
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &id); err != nil {
			return id, nil, fmt.Errorf("%s: %w", path, err)
		}
		key, err := hex.DecodeString(id.Key)
		if err != nil || len(key) != 16 {
			return id, nil, fmt.Errorf("%s: encryption_key must be 16 bytes of hex", path)
		}
		if len(id.DeviceID) == 0 {
			return id, nil, fmt.Errorf("%s: device_id is empty", path)
		}
		return id, key, nil
	}

	devID := make([]byte, 8)
	key := make([]byte, 16)
	if err := randRead(devID); err != nil {
		return id, nil, err
	}
	if err := randRead(key); err != nil {
		return id, nil, err
	}
	id = wsIdentity{DeviceID: hex.EncodeToString(devID), Key: hex.EncodeToString(key)}
	b, _ := json.MarshalIndent(id, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		return id, nil, fmt.Errorf("%s: %w", path, err)
	}
	return id, key, nil
}

// ---------------------------------------------------------------------------
// Minimal WebSocket client

type wsConn struct {
	c    net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex // one writer at a time: the ping ticker races the read loop
	idle time.Duration
}

// randReader exposes randRead as an io.Reader so the same safe source can be
// handed to crypto/tls via Config.Rand.
type randReader struct{}

func (randReader) Read(b []byte) (int, error) {
	if err := randRead(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// wsDial performs the TCP/TLS connect and the HTTP/1.1 Upgrade handshake.
func wsDial(rawURL, deviceID, caFile string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("bad -ws-url: %w", err)
	}
	secure := u.Scheme == "wss"
	if !secure && u.Scheme != "ws" {
		return nil, fmt.Errorf("bad -ws-url scheme %q (want ws or wss)", u.Scheme)
	}
	q := u.Query()
	q.Set("device_id", deviceID)
	u.RawQuery = q.Encode()

	port := u.Port()
	if port == "" {
		port = ifStr(secure, "443", "80")
	}
	// The modem and the laptop get DIFFERENT Cloudflare addresses from their
	// resolvers, so the address must be pinnable separately from the name: SNI and
	// Host stay from -ws-url, only the TCP destination changes.
	dialAddr := net.JoinHostPort(u.Hostname(), port)
	if *wsConnTo != "" {
		dialAddr = *wsConnTo
		if _, _, err := net.SplitHostPort(dialAddr); err != nil {
			dialAddr = net.JoinHostPort(*wsConnTo, port)
		}
	}
	raw, err := net.DialTimeout("tcp", dialAddr, wsDialTO)
	if err != nil {
		return nil, err
	}
	if *wsTrace {
		fmt.Printf("    dial %s → %s\n", dialAddr, raw.RemoteAddr())
	}

	var conn net.Conn = raw
	if secure {
		// Rand is not cosmetic: otherwise crypto/tls draws randomness from
		// crypto/rand, which corrupts memory on this kernel (see rand_linux.go).
		// Config.Rand propagates through the whole handshake — ECDHE and session
		// tickets alike.
		pool, err := rootPool(caFile)
		if err != nil {
			raw.Close()
			return nil, err
		}
		cfg := &tls.Config{
			ServerName: u.Hostname(),
			MinVersion: tls.VersionTLS12,
			Rand:       randReader{},
			RootCAs:    pool,
		}
		tc := tls.Client(raw, cfg)
		tc.SetDeadline(time.Now().Add(wsHandshakeTO))
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w%s", err, tlsHint(err))
		}
		if *wsTrace {
			st := tc.ConnectionState()
			fmt.Printf("    tls  version=0x%04X suite=%s\n",
				st.Version, tls.CipherSuiteName(st.CipherSuite))
		}
		conn = tc
	}

	nonce := make([]byte, 16)
	if err := randRead(nonce); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce)

	conn.SetDeadline(time.Now().Add(wsHandshakeTO))
	req := "GET " + u.RequestURI() + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"User-Agent: sms-relay\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReaderSize(conn, 2048)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading handshake response: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 101") {
		conn.Close()
		return nil, fmt.Errorf("upgrade refused: %s", strings.TrimSpace(status))
	}
	var accept string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("reading handshake headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if i := strings.IndexByte(line, ':'); i > 0 &&
			strings.EqualFold(strings.TrimSpace(line[:i]), "Sec-WebSocket-Accept") {
			accept = strings.TrimSpace(line[i+1:])
		}
	}
	// SHA-1 here is not a security choice: RFC 6455 mandates it for the handshake proof.
	sum := sha1.Sum([]byte(key + wsGUID))
	if want := base64.StdEncoding.EncodeToString(sum[:]); accept != want {
		conn.Close()
		return nil, fmt.Errorf("bad Sec-WebSocket-Accept (got %q)", accept)
	}
	conn.SetDeadline(time.Time{})
	return &wsConn{c: conn, br: br}, nil
}

func (w *wsConn) close() { w.c.Close() }

// wsTracef prints one line per frame when -ws-trace is set. Servers behind proxies have
// their own idea of keepalive, and this is the only way to see whose timer fired.
func wsTracef(dir string, op byte, n int) {
	if !*wsTrace {
		return
	}
	name := map[byte]string{opContinuation: "cont", opText: "text", opBinary: "bin",
		opClose: "close", opPing: "ping", opPong: "pong"}[op]
	fmt.Printf("    %s %s op=0x%X %-5s len=%d\n", time.Now().Format("15:04:05.000"), dir, op, name, n)
}

// writeFrame emits one masked frame. Client-to-server frames MUST be masked (RFC 6455 5.3).
func (w *wsConn) writeFrame(op byte, payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()

	var hdr [14]byte
	hdr[0] = 0x80 | op // FIN
	n := 2
	switch {
	case len(payload) < 126:
		hdr[1] = byte(len(payload))
	case len(payload) <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(len(payload)))
		n = 10
	}
	hdr[1] |= 0x80 // MASK
	var mask [4]byte
	if err := randRead(mask[:]); err != nil {
		return err
	}
	n += copy(hdr[n:], mask[:])

	body := make([]byte, len(payload))
	for i := range payload {
		body[i] = payload[i] ^ mask[i%4]
	}
	wsTracef("->", op, len(payload))
	if *wsDump {
		fmt.Printf("      TX hdr=%X mask=%X plain=%X masked=%X\n",
			hdr[:n-4], mask, payload, body)
	}
	if err := w.c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := w.c.Write(hdr[:n]); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.c.Write(body)
	return err
}

func (w *wsConn) readFrame() (op byte, fin bool, payload []byte, err error) {
	// Refresh per FRAME, not per message: ping/pong are consumed inside readMessage and
	// would otherwise never push the deadline out, killing a perfectly healthy connection.
	if w.idle > 0 {
		if err = w.c.SetReadDeadline(time.Now().Add(w.idle)); err != nil {
			return
		}
	}
	var h [2]byte
	if _, err = io.ReadFull(w.br, h[:]); err != nil {
		return
	}
	op, fin = h[0]&0x0F, h[0]&0x80 != 0
	masked := h[1]&0x80 != 0
	size := int(h[1] & 0x7F)
	switch size {
	case 126:
		var e [2]byte
		if _, err = io.ReadFull(w.br, e[:]); err != nil {
			return
		}
		size = int(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err = io.ReadFull(w.br, e[:]); err != nil {
			return
		}
		v := binary.BigEndian.Uint64(e[:])
		if v > wsMaxPayload {
			err = fmt.Errorf("frame of %d bytes exceeds %d cap", v, wsMaxPayload)
			return
		}
		size = int(v)
	}
	if size > wsMaxPayload {
		err = fmt.Errorf("frame of %d bytes exceeds %d cap", size, wsMaxPayload)
		return
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(w.br, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, size)
	if _, err = io.ReadFull(w.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	wsTracef("<-", op, len(payload))
	if *wsDump {
		fmt.Printf("      RX op=%#x fin=%v masked=%v plain=%X\n", op, fin, masked, payload)
	}
	return
}

// readMessage reassembles fragments and answers control frames inline.
func (w *wsConn) readMessage() (op byte, payload []byte, err error) {
	var msgOp byte
	var buf []byte
	for {
		o, fin, p, err := w.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch o {
		case opPing:
			// RFC 6455 5.5.3: a Pong must carry the same payload as the Ping.
			// This is the frame that went out mangled for years — see randRead in
			// rand_linux.go.
			if err := w.writeFrame(opPong, p); err != nil {
				return 0, nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			return 0, nil, fmt.Errorf("server closed the connection%s", wsCloseReason(p))
		case opText, opBinary:
			msgOp, buf = o, p
		case opContinuation:
			if msgOp == 0 {
				return 0, nil, fmt.Errorf("continuation frame without a start frame")
			}
			if len(buf)+len(p) > wsMaxPayload {
				return 0, nil, fmt.Errorf("reassembled message exceeds %d cap", wsMaxPayload)
			}
			buf = append(buf, p...)
		default:
			return 0, nil, fmt.Errorf("unexpected opcode 0x%X", o)
		}
		if fin {
			return msgOp, buf, nil
		}
	}
}

func wsCloseReason(p []byte) string {
	if len(p) < 2 {
		return ""
	}
	return fmt.Sprintf(" (code=%d %q)", binary.BigEndian.Uint16(p), strings.TrimSpace(string(p[2:])))
}

// ---------------------------------------------------------------------------
// Payload decryption

func wsDecrypt(data, key []byte) ([]byte, error) {
	if len(data) < 2*aes.BlockSize {
		return nil, fmt.Errorf("payload of %d bytes is too short", len(data))
	}
	if (len(data)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not block aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, data[:aes.BlockSize]).CryptBlocks(out, data[aes.BlockSize:])

	pad := int(out[len(out)-1]) // PKCS#7
	if pad == 0 || pad > aes.BlockSize || pad > len(out) {
		return nil, fmt.Errorf("bad padding (wrong encryption key?)")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("bad padding (wrong encryption key?)")
		}
	}
	return out[:len(out)-pad], nil
}

// ---------------------------------------------------------------------------
// Run loop

type wsRequest struct {
	Type   string `json:"type"`
	PDU    string `json:"pdu"`
	Length *int   `json:"length"`
	SMS    string `json:"sms"`
	Phone  string `json:"phone"`
}

// runWS connects to the panel and keeps reconnecting until the process is killed.
func runWS() {
	path := wsIdentityPath()
	id, key, err := loadWSIdentity(path)
	if err != nil {
		fmt.Printf("❌ identity: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("sms-relay in WebSocket mode → %s\n", *wsURL)
	fmt.Printf("device %s  cooldown=%s  logdir=%s\n", *dev, *cooldown, *logDir)
	fmt.Printf("transport: at=%s → currently %q (atserver pid=%d)\n", *atMode, pickTransport(), atServerPID())
	fmt.Println("── pair this gateway in the OpenCARWINGS panel ──")
	fmt.Printf("   Device ID      = %s\n", id.DeviceID)
	fmt.Printf("   Encryption Key = %s\n", strings.ToUpper(id.Key))
	fmt.Printf("   (stored in %s)\n", path)
	fmt.Println("─────────────────────────────────────────────────")
	if y := time.Now().UTC().Year(); y < 2020 {
		fmt.Printf("⚠️  system clock reads %s — TLS certificate validation will fail until the date is correct\n",
			time.Now().Format(time.RFC3339))
	}

	attempt := 0
	for {
		conn, err := wsDial(*wsURL, id.DeviceID, *wsCA)
		if err != nil {
			d := wsBackoff(attempt)
			attempt++
			fmt.Printf("⚠️  connect: %v — retrying in %s\n", err, d)
			logJSON(map[string]any{
				"ts": time.Now().UTC().Format(time.RFC3339), "mode": "ws",
				"result": "connect-failed", "at": err.Error(),
			})
			time.Sleep(d)
			continue
		}
		attempt = 0
		established := time.Now()
		fmt.Printf("✅ connected  rss=%s threads=%s\n", procRSS(), procThreads())
		logJSON(map[string]any{
			"ts": time.Now().UTC().Format(time.RFC3339), "mode": "ws",
			"result": "connected", "rss": procRSS(),
		})

		err = wsServe(conn, key)
		conn.close()
		lasted := time.Since(established)
		fmt.Printf("⚠️  disconnected after %s: %v\n", lasted.Truncate(time.Second), err)
		logJSON(map[string]any{
			"ts": time.Now().UTC().Format(time.RFC3339), "mode": "ws",
			"result": "disconnected", "at": fmt.Sprint(err),
			"lasted_s": int(lasted.Seconds()),
		})
		// A session that lived is evidence the server is fine, so do not punish
		// ourselves for its disconnect: retry from the shortest delay.
		if lasted >= healthySession {
			attempt = 0
		}
		d := wsBackoff(attempt)
		attempt++
		time.Sleep(d)
	}
}

// wsBackoff starts at 1s and doubles, capped at 60s.
//
// The reference gateway starts at 5s, but this endpoint drops a healthy session every
// 20-40s for reasons outside our control, and reconnecting always succeeds immediately.
// At a 6s gap roughly one in six pushed commands landed while we were away; at 1s that
// is closer to one in thirty, for about 18% more connections per hour. A genuinely
// unreachable server still backs off exponentially, because attempt only resets after
// a session that actually lived (see runWS).
func wsBackoff(attempt int) time.Duration {
	if attempt > 10 {
		attempt = 10
	}
	d := time.Second * time.Duration(1<<uint(attempt))
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

// healthySession is how long a connection must last to count as "the server was
// reachable", so that a drop afterwards retries fast instead of backing off.
const healthySession = 5 * time.Second

func wsServe(w *wsConn, key []byte) error {
	done := make(chan struct{})
	defer close(done)

	if *wsPing > 0 {
		go func() {
			t := time.NewTicker(*wsPing)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					if err := w.writeFrame(opPing, nil); err != nil {
						return // the read loop will observe the same failure
					}
				}
			}
		}()
	}

	if *wsHello != "" {
		if err := w.writeFrame(opText, []byte(*wsHello)); err != nil {
			return fmt.Errorf("sending -ws-hello: %w", err)
		}
	}

	w.idle = 3 * *wsPing
	if w.idle <= 0 {
		w.idle = 90 * time.Second
	}
	for {
		op, payload, err := w.readMessage()
		if err != nil {
			return err
		}
		if op == opText {
			// The reference client only logs these; mirror that rather than guess.
			fmt.Printf("    ws text: %s\n", oneLine(string(payload)))
			continue
		}
		plain, err := wsDecrypt(payload, key)
		if err != nil {
			fmt.Printf("    ❌ decrypt: %v\n", err)
			logJSON(map[string]any{
				"ts": time.Now().UTC().Format(time.RFC3339), "mode": "ws",
				"result": "decrypt-failed", "at": err.Error(),
			})
			continue
		}
		handleWSRequest(plain)
	}
}

func handleWSRequest(plain []byte) {
	ts := time.Now().UTC()
	var req wsRequest
	if err := json.Unmarshal(plain, &req); err != nil {
		fmt.Printf("    ❌ ws payload is not JSON: %v\n", err)
		logJSON(map[string]any{
			"ts": ts.Format(time.RFC3339), "mode": "ws", "result": "not-json",
		})
		return
	}

	switch req.Type {
	case "connect":
		fmt.Println("    ws: paired and ready")
		logJSON(map[string]any{"ts": ts.Format(time.RFC3339), "mode": "ws", "result": "ws-connect"})

	case "pdu":
		info, err := decodeSubmitPDU(req.PDU)
		if err != nil {
			fmt.Printf("    ❌ ws pdu: %v\n", err)
			logJSON(map[string]any{"ts": ts.Format(time.RFC3339), "mode": "ws", "result": "bad-pdu"})
			return
		}
		tpduLen := info.atLength
		if req.Length != nil && *req.Length > 0 {
			tpduLen = *req.Length
		}
		if !destinationAllowed(info.phone) {
			fmt.Printf("%s ⛔ ws refused: %s is not in -allow-to\n", ts.Format("15:04:05"), redact(info.phone))
			logJSON(map[string]any{
				"ts": ts.Format(time.RFC3339), "mode": "ws",
				"result": "dest-refused", "phone": redact(info.phone),
			})
			return
		}
		if !claimPDU(req.PDU) {
			fmt.Printf("%s ws -> cooldown-dup → %s\n", ts.Format("15:04:05"), redact(info.phone))
			logJSON(map[string]any{
				"ts": ts.Format(time.RFC3339), "mode": "ws",
				"result": "cooldown-dup", "phone": redact(info.phone),
			})
			return
		}
		fmt.Printf("%s ws -> queued → %s\n", ts.Format("15:04:05"), redact(info.phone))
		go sendWorker(req.PDU, tpduLen, map[string]any{
			"ts": ts.Format(time.RFC3339), "mode": "ws",
			"phone": redact(info.phone), "dcs": info.dcs, "tpdu_len": tpduLen, "type": "pdu",
		})

	case "sms":
		// Text-mode SMS (AT+CMGF=1) is not implemented: this relay is PDU-only by design.
		fmt.Printf("    ⚠️  ws: text SMS to %s ignored (PDU mode only)\n", redact(req.Phone))
		logJSON(map[string]any{
			"ts": ts.Format(time.RFC3339), "mode": "ws",
			"result": "text-sms-unsupported", "phone": redactOrNil(req.Phone),
		})

	default:
		fmt.Printf("    ⚠️  ws: unknown request type %q\n", req.Type)
		logJSON(map[string]any{
			"ts": ts.Format(time.RFC3339), "mode": "ws",
			"result": "unknown-type", "at": req.Type,
		})
	}
}

// tlsHint turns the two failure modes that actually bite on stock modem firmware into
// actionable advice instead of a bare x509 error.
func tlsHint(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "unknown authority"), strings.Contains(s, "failed to load system roots"),
		strings.Contains(s, "certificate is not trusted"):
		return "\n    hint: the endpoint's issuer is not in the embedded CA bundle — its" +
			"\n          root may have rotated (regenerate with tools/mkca.sh) or supply -ws-ca <roots.pem>"
	case strings.Contains(s, "not yet valid"), strings.Contains(s, "has expired"):
		return fmt.Sprintf("\n    hint: system clock reads %s — fix the date first", time.Now().Format(time.RFC3339))
	}
	return ""
}
