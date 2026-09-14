package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// encryptForTest mirrors what the panel does: IV || AES-128-CBC-PKCS#7(plaintext).
func encryptForTest(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	for i := 0; i < pad; i++ {
		plain = append(plain, byte(pad))
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return append(iv, out...)
}

func TestWSDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef")
	want := `{"type":"pdu","pdu":"0001000C9183902143658700000141","length":14}`

	got, err := wsDecrypt(encryptForTest(t, key, []byte(want)), key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// A wrong key must be rejected by the padding check rather than yielding garbage.
	wrong := []byte("fedcba9876543210")
	if _, err := wsDecrypt(encryptForTest(t, key, []byte(want)), wrong); err == nil {
		t.Error("expected an error when decrypting with the wrong key")
	}

	for _, short := range [][]byte{nil, make([]byte, 16), make([]byte, 31)} {
		if _, err := wsDecrypt(short, key); err == nil {
			t.Errorf("expected an error for a %d-byte payload", len(short))
		}
	}
}

// readServerFrame parses one client->server frame and asserts it was masked.
func readServerFrame(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := br.Read(h[:]); err != nil {
		t.Fatal(err)
	}
	if h[1]&0x80 == 0 {
		t.Fatal("client frame was not masked, RFC 6455 requires masking")
	}
	n := int(h[1] & 0x7F)
	var mask [4]byte
	if _, err := br.Read(mask[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, n)
	if n > 0 {
		if _, err := br.Read(body); err != nil {
			t.Fatal(err)
		}
		for i := range body {
			body[i] ^= mask[i%4]
		}
	}
	return h[0] & 0x0F, body
}

func writeServerFrame(c net.Conn, op byte, payload []byte) error {
	hdr := []byte{0x80 | op}
	switch {
	case len(payload) < 126:
		hdr = append(hdr, byte(len(payload)))
	default:
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		hdr = append(hdr, 126, ext[0], ext[1])
	}
	if _, err := c.Write(hdr); err != nil {
		return err
	}
	_, err := c.Write(payload)
	return err
}

// TestWSHandshakeAndMessage drives the real client against a local server: it checks the
// device_id query parameter, the RFC 6455 accept proof, ping/pong, and an encrypted
// binary message end to end.
func TestWSHandshakeAndMessage(t *testing.T) {
	key := []byte("0123456789abcdef")
	payload := `{"type":"pdu","pdu":"0001000C9183902143658700000141","length":14}`

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	reqLine := make(chan string, 1)
	srvErr := make(chan error, 1)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)

		line, err := br.ReadString('\n')
		if err != nil {
			srvErr <- err
			return
		}
		reqLine <- line

		var wsKey string
		for {
			h, err := br.ReadString('\n')
			if err != nil {
				srvErr <- err
				return
			}
			if h == "\r\n" || h == "\n" {
				break
			}
			if i := strings.IndexByte(h, ':'); i > 0 &&
				strings.EqualFold(strings.TrimSpace(h[:i]), "Sec-WebSocket-Key") {
				wsKey = strings.TrimSpace(h[i+1:])
			}
		}
		sum := sha1.Sum([]byte(wsKey + wsGUID))
		fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))

		// A ping must come back as a pong before anything else is read.
		if err := writeServerFrame(c, opPing, []byte("hi")); err != nil {
			srvErr <- err
			return
		}
		if op, body := readServerFrame(t, br); op != opPong || string(body) != "hi" {
			srvErr <- fmt.Errorf("expected pong %q, got opcode 0x%X %q", "hi", op, body)
			return
		}
		srvErr <- writeServerFrame(c, opBinary, encryptForTest(t, key, []byte(payload)))
	}()

	conn, err := wsDial("ws://"+ln.Addr().String()+"/ws/smsgateway/", "0011223344556677", "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.close()

	if got := <-reqLine; !strings.Contains(got, "device_id=0011223344556677") {
		t.Errorf("device_id missing from request line: %q", got)
	}

	conn.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	op, frame, err := conn.readMessage()
	if err != nil {
		t.Fatalf("readMessage: %v", err)
	}
	if op != opBinary {
		t.Fatalf("expected a binary frame, got opcode 0x%X", op)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}

	plain, err := wsDecrypt(frame, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var req wsRequest
	if err := json.Unmarshal(plain, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Type != "pdu" || req.Length == nil || *req.Length != 14 {
		t.Errorf("unexpected request: %+v", req)
	}
	if _, err := decodeSubmitPDU(req.PDU); err != nil {
		t.Errorf("PDU from the wire did not decode: %v", err)
	}
}

func TestWSBackoff(t *testing.T) {
	if got := wsBackoff(0); got != time.Second {
		t.Errorf("attempt 0: got %s, want 1s", got)
	}
	if got := wsBackoff(1); got != 2*time.Second {
		t.Errorf("attempt 1: got %s, want 2s", got)
	}
	for _, a := range []int{6, 10, 50} {
		if got := wsBackoff(a); got != 60*time.Second {
			t.Errorf("attempt %d: got %s, want the 60s cap", a, got)
		}
	}
}

func TestDestinationAllowlist(t *testing.T) {
	saved := allowedDest
	defer func() { allowedDest = saved }()

	allowedDest = nil
	if !destinationAllowed("380912345678") {
		t.Error("an empty allowlist must permit every destination")
	}

	allowedDest = []string{"380912345678"}
	for _, ok := range []string{"380912345678"} {
		if !destinationAllowed(ok) {
			t.Errorf("%s should be allowed", ok)
		}
	}
	for _, bad := range []string{"380912345679", "", "12345678", "3809123456789"} {
		if destinationAllowed(bad) {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestNormalizeMSISDN(t *testing.T) {
	for in, want := range map[string]string{
		"+380 91 234-56-78": "380912345678",
		"380912345678":      "380912345678",
		"":                  "",
		"++--":              "",
	} {
		if got := normalizeMSISDN(in); got != want {
			t.Errorf("normalizeMSISDN(%q) = %q, want %q", in, got, want)
		}
	}
}

// bufConn is a minimal net.Conn that only accumulates what is written.
type bufConn struct {
	net.Conn
	written []byte
}

func (b *bufConn) Write(p []byte) (int, error) {
	b.written = append(b.written, p...)
	return len(p), nil
}
func (b *bufConn) SetWriteDeadline(time.Time) error { return nil }

// TestWriteFrameBytes pins the exact bytes of the frame we put on the socket.
// This is deliberately checked at the byte level and without a network: the
// investigation showed the client behaves differently on the modem than on a
// laptop, and we must be able to tell an arithmetic bug on specific hardware
// from a network problem.
func TestWriteFrameBytes(t *testing.T) {
	payload := []byte{0x18, 0xD4, 0xE0, 0x53, 0xFE, 0x46, 0x1B, 0x5B, 0x00, 0x00, 0x00, 0x01}
	bc := &bufConn{}
	w := &wsConn{c: bc}

	if err := w.writeFrame(opPong, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	got := bc.written

	if len(got) != 2+4+len(payload) {
		t.Fatalf("frame is %d bytes, want %d: %X", len(got), 2+4+len(payload), got)
	}
	if got[0] != 0x8A {
		t.Errorf("byte 0 = %#02x, want 0x8A (FIN|pong) — whole frame: %X", got[0], got)
	}
	if got[1] != 0x8C {
		t.Errorf("byte 1 = %#02x, want 0x8C (MASK|len=12) — whole frame: %X", got[1], got)
	}
	mask := got[2:6]
	unmasked := make([]byte, len(payload))
	for i := range payload {
		unmasked[i] = got[6+i] ^ mask[i%4]
	}
	if string(unmasked) != string(payload) {
		t.Errorf("payload does not survive the mask: got %X want %X", unmasked, payload)
	}
}
