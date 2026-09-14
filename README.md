# sms-relay

**sms-relay** is an ultra-lightweight, on-device webhook relay designed to run directly inside ARM-based Linux LTE USB modems and mobile routers (such as **ZTE MF79U**, **ZX297520V3** chipsets, and similar embedded Linux modems).

It relays SMS-SUBMIT PDUs from **OpenCARWINGS** (or other automotive telematics / home-automation controllers) to the modem's onboard AT command interface — no host PC, no external modem daemons. It runs in two modes:

- **`-mode ws` (default)** — an outbound WebSocket client that dials the OpenCARWINGS gateway and holds the connection open, so the modem needs **no inbound path**: no port forwarding, no tunnel, and carrier-grade NAT on the cellular side stops mattering. This is the primary mode.
- **`-mode http` (fallback)** — an inbound HTTP webhook server, for LAN-local or tunneled setups where something in front POSTs the PDU to the modem.

> [!NOTE]
> **Platform Target**: `sms-relay` is engineered for embedded Linux-based modem environments (`GOOS=linux`). Cross-compilation for non-Linux hosts (macOS, Windows) compiles cleanly for static analysis and development, while hardware device node transport (`/dev/rpm30`) executes on Linux targets.

---

## Key Features & Hardware Engineering Highlights

- **Zero-Dependency Lightweight HTTP Engine**:
  Modems like the ZTE MF79U typically operate under severe RAM constraints (~5-6 MB free memory). Standard Go `net/http` server overhead triggers the Linux Out-Of-Memory (LMK) process killer. `sms-relay` implements a low-allocation, single-connection HTTP/1.1 server using raw `net.Listener`, keeping memory consumption minimal.

- **Dual AT Transport Modes**:
  - **`atsrv` (Primary Unix Socket)**: Interacts with the stock `/bin/atserver` via `/tmp/zte_socket/AT_SERVER_MSG`. Because `atserver` is the single owner of `/dev/rpm30`, this mode prevents AT response corruption caused by background cellular status polling (`+CESQ`). It also handles two-stage `AT+CMGS` PDU framing internally.
  - **`rpm30` (Direct Device Node)**: Communicates directly with `/dev/rpm30` using a non-blocking `select(2)` event loop. This solves kernel driver bugs in `zx29_rpmsg` where raw `syscall.Read` ignores `O_NONBLOCK` and permanently strands OS threads in uninterruptible sleep (`D`-state).

- **Integrated `atserver` Watchdog**:
  Monitors the background `/bin/atserver` process via `/proc` and automatically re-spawns it if it crashes (since standard `pppd` cellular data connections depend on `atserver`).

- **Deduplication & Exponential Backoff**:
  Implements configurable cooldown periods for identical PDU payloads to mute duplicate HTTP retries, alongside exponential backoff (up to 2 hours) after consecutive AT command failures to prevent destabilizing the cellular baseband stack.

- **Privacy & Security**:
  - The `/hook` endpoint is secured with a secret URL path component (`/hook/<secret>`) provided via `-secret` or `SMS_RELAY_SECRET` environment variable using constant-time string comparison.
  - Logs phone numbers in redacted format (e.g. `3809…78`) to protect user privacy.

---

## Architecture & Data Flow

The diagram below shows the **HTTP fallback** (`-mode http`), where a controller POSTs the PDU inbound. In the default **WebSocket mode** (`-mode ws`) the arrow reverses: the relay dials **out** to the OpenCARWINGS gateway and receives PDUs over the open connection — the AT-transport half (everything below `sms-relay`) is identical.

```
+--------------------------+       HTTP POST       +------------------------------------+
| Telematics / Controller  | --------------------> |             sms-relay              |
|  (e.g., OpenCarWings)    |  /hook/<secret> JSON  |  (Runs directly on LTE Modem Linux)|
+--------------------------+                       +------------------------------------+
                                                                     |
                                             +-----------------------+-----------------------+
                                             |                                               |
                                     (Primary: atsrv)                                (Fallback: rpm30)
                                             v                                               v
                                   +-------------------+                           +-------------------+
                                   |  /bin/atserver    |                           | (Raw character    |
                                   | (Unix Socket IPC) |                           |  device node)     |
                                   +-------------------+                           +-------------------+
                                             |                                               |
                                             +-----------------------+-----------------------+
                                                                     v
                                                          +--------------------+
                                                          |  ZTE LTE Baseband  |
                                                          | (Binary SMS PDU)   |
                                                          +--------------------+
```

---

## Installation & Binary Releases

> [!NOTE]
> Obtaining shell access on the modem is device- and firmware-specific (stock ZTE firmware typically ships without SSH).
> Once you have file system access, place the `sms-relay` binary into persistent storage (e.g., `/cache/`) and grant execution permissions (`chmod +x /cache/sms-relay`).

### Prebuilt Binaries

Prebuilt ARM binaries and release archives are available on the [Releases](../../releases) page:

- `sms-relay` — Precompiled Linux ARMv5/ARMv7 binary
- `sms-relay-linux-armv5.tar.gz` — Archive containing binary, README, and LICENSE
- `checksums.txt` — SHA-256 checksums for verifying download integrity

Verify integrity via checksums:

```bash
sha256sum -c --ignore-missing checksums.txt
```

### Build From Source

The modem's kernel breaks stock `crypto/rand` (see [`toolchain_guard.go`](toolchain_guard.go) for the full story), so the **supported build patches the Go standard library at build time** with `go build -overlay` — there is no fork of Go, and a current toolchain (Go 1.27) works:

```bash
go run ./toolchain/mkoverlay -out /tmp/ovl
GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 \
  go build -overlay=/tmp/ovl/overlay.json -tags patchedstdlib \
  -trimpath -ldflags "-s -w" -o sms-relay .
```

A build guard fails loudly on Go ≥ 1.24 **without** `-tags patchedstdlib`, so you cannot accidentally ship a binary that dies on the device. As a fallback, Go 1.23.12 builds without the overlay — but only because the in-code `/dev/urandom` workaround bypasses the broken stock `crypto/rand` (which on 1.23 returns success while silently corrupting memory); 1.23 itself is still affected, and out of support:

```bash
GOTOOLCHAIN=go1.23.12 GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o sms-relay .
```

---

## Command Line Usage

Default (WebSocket mode) — no secret and no inbound path needed; it prints a Device ID
and Encryption Key to pair in the OpenCARWINGS panel on first run:

```bash
/cache/sms-relay [options]
```

Fallback (HTTP webhook mode) — requires a secret protecting the `/hook` endpoint:

```bash
/cache/sms-relay -mode http -secret <YOUR_SECRET_TOKEN> [options]
# Or using environment variable:
SMS_RELAY_SECRET=<YOUR_SECRET_TOKEN> /cache/sms-relay -mode http [options]
```

### Options & Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-secret` | `""` | Secret path component (`POST /hook/<secret>`). Can also be set via `SMS_RELAY_SECRET` env var. |
| `-dev` | `/dev/rpm30` | ZTE modem AT device node path. |
| `-listen` | `192.168.0.1:8787` | IP host and port binding (LAN binding recommended). |
| `-at` | `auto` | AT transport mode: `auto` (prefers atserver if running), `atsrv`, or `rpm30`. |
| `-atsock` | `/tmp/zte_socket/AT_SERVER_MSG` | Unix socket path for stock `atserver`. |
| `-atbin` | `/bin/atserver` | Path to `atserver` binary for process watchdog. |
| `-watchdog`| `60s` | Check interval for `atserver` watchdog (`0` to disable). |
| `-cooldown`| `90s` | Minimum cooldown duration between duplicate PDU transmissions. |
| `-logdir` | `/cache/sms-relay-log` | Directory for persistent JSON log files. |
| `-logurl` | `false` | Expose `GET /log/<secret>` endpoint via HTTP (disabled by default). |
| `-report` | `false` | Enable `+CDS` delivery report request and TP-ST status logging. |
| `-reqlog` | `false` | Log incoming HTTP request headers and timing diagnostics to `reqlog.jsonl`. |
| `-debug` | `false` | Verbose step-by-step markers and raw body dump in `debug.log`. |
| `-selftest`| `0` | Run `N` self-test AT cycles, output thread metrics, and exit. |
| `-allow-to` | `""` | Comma-separated recipient MSISDNs the relay may send to (empty = any). Applies to both modes; a compromised panel then cannot use the SIM to text anyone else. |
| `-memlog` | `0` | Periodically log `VmRSS` and thread count (`0` = off) — for RAM budgeting on the modem. |

---

## WebSocket Mode & TLS Trust

With `-mode ws`, the relay dials **out** to the OpenCARWINGS gateway and holds the
connection open, so the modem needs no inbound path — no port forwarding, no
tunnel, and carrier-grade NAT on the cellular side stops mattering.

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | `ws` | `ws` (outbound OpenCARWINGS WebSocket client, default) or `http` (inbound webhook server, fallback). |
| `-ws-url` | `wss://opencarwings.viaaq.eu/ws/smsgateway/` | Gateway WebSocket URL. |
| `-ws-identity` | `<logdir>/ws-identity.json` | Device identity file (device ID + encryption key). Auto-generated on first run; paste the printed values into the panel to pair. |
| `-ws-ping` | `30s` | Keepalive ping interval (`0` = disable). |
| `-ws-ca` | `""` | PEM of **extra** root CAs, added to the embedded bundle. |

On first run in `-mode ws` the relay prints the Device ID and Encryption Key to paste into the OpenCARWINGS panel, then keeps reconnecting on its own.

For protocol debugging there are also `-ws-trace` (log every frame), `-ws-dump` (hex-dump frame bytes), `-ws-hello` (send a text frame after the handshake), and `-ws-connect-to` (dial a specific edge `host:port` while keeping the SNI/Host from `-ws-url`).

Stock modem firmware ships no `/etc/ssl/certs`, so the binary carries its own
minimal CA bundle (`ca/roots.pem`, embedded at build time). It contains the
Google Trust Services and Let's Encrypt (ISRG) root families plus the GlobalSign
cross-sign anchor — the issuers a Cloudflare-fronted endpoint rotates between — so
TLS keeps validating across a rotation without a new binary.

`-ws-ca` **adds** to that embedded set (and to the host's system roots, if any); it
does not replace them. Use it to trust a different endpoint, or as an escape hatch
if the endpoint's root ever rotates to one the bundle has not caught up with.

The roots are public certificates (not secrets), documented with their sources and
SHA-256 fingerprints in [`ca/README.md`](ca/README.md). CI keeps them honest: a
**reproducibility** check re-runs `tools/mkca.sh` and fails if the committed bundle
is not byte-identical to what the authoritative CA publishers serve, and a weekly
**canary** TLS-dials the default endpoint against `ca/roots.pem` alone so a rotation
surfaces before it reaches a device.

To refresh the embedded bundle after a known root rotation:

```bash
sh tools/mkca.sh && git diff ca/roots.pem
```

---

## Webhook API Specification

### `POST /hook/<secret>`

Receives the JSON payload containing the binary SMS SUBMIT PDU.

#### Request Headers:
```http
Content-Type: application/json
```

#### Request Payload:
```json
{
  "message": "Wakeup command",
  "type": 1,
  "pdu": "0001000C9183902143658700000141",
  "pdu_length": 14
}
```

- **`pdu`**: Hex-encoded binary SMS-SUBMIT PDU (with destination address encoded inside).
- **`pdu_length`**: TPDU length (in octets). If set to `0`, `sms-relay` automatically decodes the length from the PDU header.

#### Response:
```http
HTTP/1.1 200 OK
Content-Length: 0
Connection: close
```
*(Returns 200 OK immediately; PDU transmission is dispatched asynchronously in the background).*

---

### `GET /health`

Health check endpoint.

#### Response:
```http
HTTP/1.1 200 OK

ok
```

---

## Self-Test & Diagnostics

You can verify the transport layer and ensure OS thread stability on the modem without transmitting SMS over cellular:

```bash
/cache/sms-relay -selftest 10
```

Sample Output:
```text
selftest: 10 cycles, transport="atsrv" (SMS sending disabled)
  socket /tmp/zte_socket/AT_SERVER_MSG, atserver pid=1240, gap between requests 300ms
   1: AT="OK"       CSQ="+CSQ: 24,99  OK" atserver=1240
   ...
selftest: 10/10 clean, atserver pid=1240 (was 1240) ✅ stable
```

---

## License

This project is licensed under the [MIT License](LICENSE).
