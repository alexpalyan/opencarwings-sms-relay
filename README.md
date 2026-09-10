# sms-relay

**sms-relay** is an ultra-lightweight, on-device webhook relay designed to run directly inside ARM-based Linux LTE USB modems and mobile routers (such as **ZTE MF79U**, **ZX297520V3** chipsets, and similar embedded Linux modems).

It receives incoming HTTP webhooks containing raw SMS SUBMIT PDUs (e.g., from **OpenCarWings** or automotive telematics/home automation controllers) and transmits binary SMS messages over the modem's onboard AT command interface without requiring an external host PC or external modem daemons.

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

To cross-compile `sms-relay` manually for ZTE ARMv7 / ARMv5 soft-float modem architecture:

```bash
GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sms-relay .
```

---

## Command Line Usage

```bash
/cache/sms-relay -secret <YOUR_SECRET_TOKEN> [options]
# Or using environment variable:
SMS_RELAY_SECRET=<YOUR_SECRET_TOKEN> /cache/sms-relay [options]
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
