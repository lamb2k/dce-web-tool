# Private Ethernet gateway

Native fixture support implemented. Actual browser game join and native OpenCE
gameplay remain unqualified. No game binaries, gateway binaries, secrets or third
party source belong in this directory. Game RAM/VRAM/AICA cost: **0 bytes**.

## Build

Use private Linux task directory with `libslirp/` checkout at exact commit in
`dependencies.json`, and `deps/` containing privately extracted listed Ubuntu
packages. `apt download` plus `dpkg-deb -x` suffices; no system installation,
privileged network interface or network configuration needed. Verify downloaded
package SHA256 values against lock file before extracting.

```sh
HALO_GATEWAY_BUILD_ROOT="$PRIVATE_BUILD_DIR" bash gateway/build-helper.sh
HALO_GATEWAY_BINARY="$PRIVATE_BUILD_DIR/gateway" python3 -m unittest discover \
  -s gateway -p 'test_*.py'
```

Build uses GCC `-Wall -Wextra -Werror`, static libslirp and privately extracted
dynamic GLib. Keep dependencies beside built helper; embedded rpath points there.
Do not copy executable alone or expose build directory through HTTP.

## Trusted launcher and proxy contract

`server.py` binds **127.0.0.1 only**, default port18106. Configure server process:

- `HALO_GATEWAY_BINARY`: absolute path to pinned built helper.
- `HALO_BRIDGE_SECRET`: random printable secret, at least32 characters; injected
  from private mode0600 file, never argv/query/browser/log. Child helper receives
  only minimal LANG/PATH environment, no authentication secret.
- `HALO_GATEWAY_PORT`: optional loopback listener port.
- `HALO_GATEWAY_MODE`: `room` default or `native`.
- Native mode additionally fixes `HALO_NATIVE_HOST` numeric reachable unicastIPv4
  and `HALO_NATIVE_PORT` (default5150) in server configuration, not browser request.
- Optional directory access requires all three independent operator pins:
  `HALO_DIRECTORY_HOST` (lowercase hostname), `HALO_DIRECTORY_IPV4` (one explicitly
  resolved address), `HALO_DIRECTORY_VERIFY_KEY` (64hex public Ed25519 key).
  Directory disabled unless all supplied. Never reuse native pool identity for a
  new DCE pool. This public key is a configuration identity pin; guest DIRDCE.CFG
  and client verify signed responses and TLS certificates. Gateway cannot verify
  encrypted response signatures. No current production DCE values configured.
- `HALO_DIRECTORY_PRIVATE_LAN_CIDRS`: optional comma-separated list, maximum4
  explicit RFC1918 CIDRs, solely for controlled same-LAN directory targets. Default
  rejects private, reserved, loopback, link-local, multicast and guest-subnet
  catalogue endpoints. No wildcard CIDR or loopback override.
- Optional fixed HOST mapping requires **all four** `HALO_GAME_BIND_IPV4`,
  `HALO_GAME_BIND_PORT`, `HALO_GAME_ADVERTISED_IPV4`, `HALO_GAME_ADVERTISED_PORT`.
  Actual bind must succeed; wildcard/loopback/link-local/guest addresses refused.
  Values are operator configuration, never HTTP request data. Default remains
  random loopback forward with no advertisable endpoint. Source support does not
  activate an external listener; operator must approve its configuration.

HTTP requests require server-only `X-Halo-Bridge-Key`, `X-Halo-Session` (64 lowercase
hex HMAC fingerprint), `X-Halo-Session-Expires` (epoch milliseconds). Upstream
proxy owns tester authentication, exact browser Origin, TLS and request rate limits.
Gateway independently validates shared key, session ownership and expiry. Never
point unauthenticated Internet traffic at this listener or publish a general proxy.

- `POST /api/guest-network`, empty body: creates/reuses caller lease,201JSON.
- `GET /api/guest-network/<lease>`: owner metadata,200JSON; with standard RFC6455
  Upgrade handshake, opens one WebSocket attached to live helper.
- `DELETE /api/guest-network/<lease>`: closes helper and mapping,204empty.

Lease ID:43base64url characters from32 random bytes. Metadata: `lease`,
`expiresAt`, `guestIPv4`, `routerIPv4`, `netmask`, `mode` (`dce`/`native`),
`role` (`host`/`peer`/`native`), `joinEndpoint` null or `{host,port}`, and exact
relative `websocketPath`. `advertisedEndpoint` is null by default; fixed HOST
mapping returns configured `{host,port}` without claiming public reachability.
Proxy preserves this only for DCE host metadata and strips other fields.
Max2 leases, max600s, bounded by authenticated session
expiry. Closing host also closes dependent peer. First DCE participant owns HOST;
second gets JOIN endpoint using its router alias and host's leased loopback port.
With fixed mapping, second gets actual configured bindIPv4:bindport. Guest's
DCEDIR02 advertised_port must equal configured external advertisedport; its normal
game socket stays5150. Registry outbound challenge/ACK proves the actual endpoint.
For NAT port translation, bindport and advertisedport can differ only through an
explicit operator mapping; no automatic NAT/router/firewall modification occurs.
Game menu still requires ordinary HOST/JOIN. Metadata never claims game admission.

WebSocket: one complete masked client binary message per raw Ethernet frame,
14..1514bytes without FCS, only ARP/IPv4. No fragmentation, compression, VLAN,
jumbo, text commands or target selection. Ping/pong supported. Disconnect closes
lease; reconnect requires fresh lease. Native helper IPC uses BE16length + frame
over inherited stdin/stdout pipes. Never expose those pipes as unauthenticated IPC.

## Network and resource boundaries

One libslirp process per lease isolates fixed Flycast BBA MAC
`0c:0a:0f:0e:00:00`. Subnet10.77.N.0/24, guest.15, router.2. DCE host forward
binds127.0.0.1:leasedPort→guest:5150/UDP; peer egress permits only its router
alias:leasedPort/UDP. Host replies allowed only to32 recent tuples learned from
actual inbound stack frames. Native mode permits only configured IPv4:port,
both TCP and UDP. DHCP/ARP validated separately. Source spoofing, IP options,
fragments, unknown protocols and all other destinations rejected before libslirp.
General DNS/IPv6/TFTP/SMB/emulation helpers not enabled. Destination ACL is primary boundary;
this is not an OS sandbox against a libslirp vulnerability. Run nonprivileged in
deployment and keep secret outside helper environment.

Optional directory mode supplies virtual DNS at10.77.N.3 via DHCP. It synthesizes
only A/IN replies for exact configured hostname from pinnedIPv4, TTL30s; no recursive
resolver, TCPDNS, EDNS, compression, AAAA or arbitrary names. Other DNS is refused.
TCP443 permits only pinnedIPv4, then holds initial application packets until a
bounded TLS ClientHello contains exact configured SNI. Shared CDN IP alone is
insufficient.8flows,8held frames each,8192byte ClientHello perflow; require one TLS
record, established SYNACK, matching sequence/ACK, valid checksums and20byte TCP
header on initial application segments. Unsupported client options fail closed;
actual guest TLS compatibility remains a runtime gate. This is an SNI restriction,
not decrypted HTTP path/Host inspection; application origin must also reject domain
fronting. TLS certificate and master signature verification remain guest duties.

Directory TCP response path is the connected native socket through libslirp; DNS
replies are local and preserve requested transaction/sourceport. DCE public host
advertisement is **not available** with default loopback hostforward. Fixed mapping
is source-ready, but configured endpoint is not evidence of WAN reachability. No
guessed public IP, private guest IP or old HELLO proof is advertised.

## Signed catalogue admission

Trusted parent fetches configured hostname at pinnedIPv4:443, validates TLS using
system CA trust, then verifies exact body using pinned Ed25519 master public key
through installed `cryptography` (validated41.0.7, no handwritten crypto).
GET `/v1/dce/servers?limit=32`; maximum32768byte body, exact signature key id,
Signature-Time within30s, bodymaster.time equality, lowercase `dce-net` family,
networkversion3, strict row bounds and endpoint ownership IDs. Go-produced signed
fixture cross-checks interoperability. Response/tuple expiry maximum90s; timestamp
rollback refused. Fetch refresh every10s. Each fetch uses killable5s subprocess
with96MiB address-space/32FD caps, so slow-drip HTTP cannot strand a background
thread. Failure clears catalogue permission immediately.

At most32 live exact IPv4+UDPport tuples admitted. Guest JOIN sourceport5151 only;
catalogue game ports1024..65535 per frozen DCE directory protocol.
ordinary DCE packets unchanged. Parent sends complete snapshots over a separate
inherited pipe, **not** Ethernet stdin or WebSocket commands: BE16payloadlength,
version1byte,count1byte,generationBE32, then count*(IPv4network4,portBE16,TTLBE16).
Maximum262byte payload; monotonic generation; TTL1..90s; malformed/partial/controlEOF
closes helper. Both guest egress and incoming reply delivery check current tuple
expiry. Revoked tuple socket can remain internal to libslirp until its timeout;
packet access is immediately denied, and all sockets close at lease/session end
through `slirp_cleanup`. Native API has no individual outbound-socket close call.

Browser cannot write control pipe, choose destinations, choose signing keys, or
inject an unsigned list. No generalized private-network permission follows from
directory setup; controlled LAN CIDRs require explicit operator configuration.

Helper:32 output frames (48,512bytes including IPC prefixes),1516byte input,
1s partial-frame/queued-age bound,1000frames/s,64MiB address-space cap,
64descriptor cap, finite lease. Async adapter:16 accepted connections maximum,
8KiB HTTP header limit,3s header timeout,24KiB helper StreamReader threshold
(asyncio pauses after twice threshold),48KiB writer highwater + one bounded frame,
1s drain/partial-message timeout. Kernel socket/pipe buffers and libslirp allocations
are additional; queue capacity is not a claim about total RSS. No unlimited
application retry queue. No guest packet payload logs.

2026-11-04 final candidate Linux `/proc` snapshots: helper afterARP
RSS3072KiB,VmSize5804KiB; idle adapterRSS26112KiB,VmSize34588KiB;
temporary fetch duringTLS RSS27264KiB,VmSize34212KiB.
Each1thread; these are separate fixture snapshots, not a combined peak.
`getrusage` maxrss can include fork/exec parent's earlier peak; use proc RSS for attribution.

## Evidence and limits

Fixtures use real libslirp and local UDP/TCP sockets, no emulator automation:
DHCP/ARP; peer→host5150 plus reply through two isolated stacks; native TCP data
and UDP data/replies on same explicitly configured endpoint; ACL refusals;
malformed IPC; lifetime; released host-forward port; HTTP auth/session ownership,
max2, actual ARP over WS, invalid WS close and cleanup. WAN routing, deployed TLS,
browser gameplay, OpenCE native admission, latency and two-device play are separate
gates. User performs actual two-device test.

Source references: [pinned libslirp API](https://gitlab.freedesktop.org/slirp/libslirp/-/blob/9c744e1e52aa0d9646ed91d789d588696292c21e/src/libslirp.h)
(`slirp_new`, `slirp_input`, send_packet/poll callbacks, hostfwd, cleanup),
[QEMU user-mode network description](https://www.qemu.org/docs/master/system/devices/net.html#using-the-user-mode-network-stack).
Game ports: host 5150, client 5151, over TCP and UDP. This adapts emulator
Ethernet transport only; no OpenCE/gameplay wire packets or timings changed.
ClientHello/SNI field references: [RFC5246 section7.4.1.2](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.2)
and [RFC6066 section3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
Signature verification: [cryptography Ed25519 API](https://cryptography.io/en/41.0.7/hazmat/primitives/asymmetric/ed25519/).

## Optional device enrollment

Disabled unless `HALO_ENROLLMENT_URL`, `HALO_ENROLLMENT_TOKEN_FILE`, and
`HALO_ENROLLMENT_MASTER_KEY` are configured together. The upstream must be a
literal loopback origin. Token file permissions must be0600; token is32..64 bytes
encoded lowercase hex. The master public pin must match the directory pin when
both are configured. No private device key or VMU bytes enter this interface.

Authenticated form sessions use POST `/api/device-enrollment/config`,
`/challenge`, and `/register`. Exact Origin and a fresh Worker HMAC session binding
are required. Basic authentication alone cannot enroll. The gateway verifies the
Go operator's Ed25519 response bytes and signed UTC, then binds device proof to
master/public key/challenge/expiry/session. Browser must durably save encrypted
VMU before registering. Approval does not establish UDP reachability or gameplay.

Bounds:512-byte requests,2048-byte signed responses,64 session rate records,
32 pending challenges,one per session,2 operator children at most; each child
has a5-second deadline and96MiB address-space cap. Config/challenge/register
quotas are30/5/10 per minute per session. Cancellation kills the child and releases
its reservation. These are allocation/admission limits, not measured total RSS.
Dreamcast RAM/VRAM/AICA delta0 bytes.

`test_enrollment.py` exercises quotas, cancellation, proof/session binding and
actual authenticated gateway routes. Set `HALO_ENROLLMENT_TEST_BINARY` to the
isolated Go enrollment binary to run real signed approval/durable readback/retry
and wrong-pin/auth fixtures. That fixture launches only ephemeral loopback
listeners with synthetic identities and temporary state. It never restarts the
configured gateway or directory. Browser VMU, deployment, WAN and paired gameplay
remain separate acceptance gates.

## Roles and verified destinations

POST may carry `X-Halo-Guest-Role: host|join` (tester page `#role=host` or `#role=join`). Absent
keeps the old rule: first lease hosts, second is peer. `join` with a room host is a peer. `join`
with no host is a `guest`: helper mode that may send only DHCP, ARP, the fixed directory DNS/TLS
and UDP from 5151 to a live signed catalog IP+port. It needs the directory and control pipe, or
it refuses to start. No request names a destination. The catalog gates new flows only. Once a
tuple has replied it stays open for that lease until 20s without a reply (game drop timer is 15s)
or lease end, at most 32 flows, none evicted. A failed fetch changes nothing: verified rows last
until their signed expiry. A response that fails verification clears the rows, so new flows
stop; established flows continue. Catalog refresh every 10s; row TTL at most 90s.

Test allowance, off by default, launcher environment only, needs the directory configured:
`HALO_GATEWAY_TEST_DESTINATION=<ipv4>:<port>`. Guest leases only. On: set it for the server
process and restart. Off: unset it and restart. While on, gateway log prints `TEST DESTINATION ACTIVE`
at start and per lease, and counter rows carry `test_destination:true`.

## Lease renewal and traffic counters

`POST /api/guest-network/<lease>` by its owner grants a fresh bounded TTL: expiry becomes
the earliest of now+600s, session expiry and helper end. Max2 leases and auth are unchanged. The helper now
starts for up to its 3600s cap, so a session cannot outlive one hour: the last renewal stops
growing, the browser reports renew state final, then the lease expires and guest networking
ends (`terminalReason` 2). A new boot gets a new lease. Failed renewals are counted and retried
every 15s until expiry. Closing the socket releases the lease, so the later cleanup DELETE
normally answers 404; helper and mapping are already gone, so this is not a leak.

`HALO_GATEWAY_COUNTERS_FILE` (optional) receives one JSON row per lease at close: frames and
bytes per direction, open time, sanitized close reason, heartbeat and renewal counts and helper
STOP numbers. One lease carries at most one connection. No token, session, address or payload.
Bounded: 64KiB plus one rotated copy, last 64 rows in memory.
