# Public native stream routing repair

Status: deployed and accepted on 22 November 2026. The managed Tunnel is at
version 5. Both new units are installed; the socket is enabled for boot.

`https://stream.blockzilla.dev/v2/banks/head` now reaches the live native
origin with its current Bearer key. Stream access remains authenticated.
The archive API at `https://archive.blockzilla.dev/block/{slot}.json` remains
separate and keyless. The old public relay key intentionally returns 401;
this repair does not translate or rotate credentials.

The [acceptance receipt](evidence/acceptance.json) checked missing, wrong,
legacy and URL-key rejection; exact next block/root frames; all object
hashes; and original-byte equality against the private Unix origin. The
finite block chunk was 293,859 bytes, with all 12 object hashes checked.
A fresh getBlock for slot 472685344 returned 200 through the unchanged
private native route, with zero R2 or S3 reads.

Validator, producer, Bank worker, origin, controller, reader and Tunnel PIDs
and invocations stayed unchanged, with zero restarts. The source authority
hash and 0600 socket mode also stayed unchanged. Only the new proxy started.
Its sampled RSS was 6,536 KiB, with 17 open FDs under its 64 MiB/512-FD caps.
These bounded checks do not establish a browser/CORS or general latency guarantee.

The [before](evidence/tunnel-before.json) and [after](evidence/tunnel-after.json)
configurations retain the exact private port-18962 rule first. The existing
Tunnel process [accepted version 5](evidence/tunnel-applied.json) without a
restart. The unit files [passed systemd validation](evidence/unit-validation.json).
No key or block payload was copied to these records.

An [earlier checker failure](evidence/checker-stale-apex-url.json) used the
retired apex archive URL and received the website HTML. Its stream checks
had passed. The final run used the current archive hostname and passed.

Before the repair, public `stream.blockzilla.dev` pointed to the closed
loopback port 8871. The old `hivezilla-stream-relay.service` was
disabled and inactive, with no job, socket or trigger. Its only reverse
dependent is a disabled, failed token demo. No automatic rebind is queued.

The current native origin is healthy on
`/home/ubuntu/live/hivezilla-validator-20260930/runtime/live/origin.sock`.
It has no concurrent TCP listener: direct mode requires a Unix socket. The
Tunnel process cannot read this socket directly. Its dynamic user has
`ProtectHome=yes`; the socket is mode 0600, owned by `ubuntu`, under private
directories. Do not change those permissions or the Tunnel sandbox.

## Small bridge

The two adjacent unit files use the installed
`/usr/lib/systemd/systemd-socket-proxyd`, systemd 259.5. The socket binds only
`127.0.0.1:8871`. Its service runs as `ubuntu`, with a read-only home and no
capabilities. It opens the current Unix socket for each new TCP connection.
It does not read a token file, parse HTTP, store blocks, change cursors, or
change the native data format. The installed program supports this
[TCP-to-Unix socket activation](https://www.freedesktop.org/software/systemd/man/259/systemd-socket-proxyd.html).

The v259 implementation uses `splice` and two pipe buffers of at most 256 KiB
per connection. The bridge has eight connections, a 64 MiB memory cap and
512 file descriptors. The native origin allows 16 requests, so this bridge
leaves capacity for its private clients and guard checks. An active stream
has no runtime limit. Only an empty service exits after five idle minutes;
the listening socket stays ready for activation. See the
[pinned implementation](https://github.com/systemd/systemd/blob/v259/src/socket-proxy/socket-proxyd.c).

No validator, producer, Bank worker, native origin or Tunnel restart was used.
No ACL, capability, key, R2 publisher or archive change was made. Only the new
socket unit is enabled; systemd starts the bridge on demand.

## Tunnel allowlist

Use the existing remotely managed Tunnel
`0cd18a26-d76a-408c-a1fa-55a1151fa3ae`. Save its exact configuration before
the change and reject concurrent configuration drift.

Keep every private getBlock rule for port 18962 unchanged and first. Then
route only these native read paths to the new loopback bridge:

```yaml
- hostname: stream.blockzilla.dev
  path: ^/v2/banks/(head|events|beam|chunks/[0-9a-f]{64})$
  service: http://127.0.0.1:8871
- hostname: stream.blockzilla.dev
  service: http_status:404
```

Preserve all other hostnames, origin settings and the final catch-all rule.
Replace the old hostname-wide port-8871 fallback with the 404 rule. Do not
leave that broad fallback behind the allowlist: it would reach origin-only
`state`, `ack` and `coverage-gaps` routes. The ingress rule checks paths;
the origin supplies GET/HEAD handlers and rejects other methods.

Cloudflare forwards the full path and query. No rewrite or new public prefix
is required. Its HTTP service can use a Unix socket, but the current Tunnel
sandbox makes the loopback bridge necessary here. See the official
[routing](https://developers.cloudflare.com/tunnel/concepts/routing/) and
[path forwarding](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/) contracts.

## Authentication and local proof

The bridge forwards the Bearer header unchanged. The current native origin
key is different from the old public relay client key. The old key must
continue to get 401. Do not translate keys, insert a key at the proxy, accept
URL keys, print a token or copy it to a report. An authorized HTTPS check can
read the existing key on Foundation and keep it in RAM.

Before any change, local Unix HTTP checks passed:

| Read | Result |
| --- | --- |
| Head, missing or wrong key | 401 |
| Head, legacy public relay client key | 401 |
| Head, valid header plus a URL key | 401 |
| Head, current native key | 200; `live`; source lag 210 ms |
| Beam HEAD, exact current cursor | 200; matching start cursor |
| `/health` | 404; this origin has no health route |

Successful reads had `Cache-Control: no-store` and `X-Accel-Buffering: no`.
Head used `application/json`; beam used
`application/vnd.blockzilla.stream.v2`. These header checks do not prove
public long-stream latency or rule out Cloudflare buffering. Test a bounded
public read after deployment before changing a consumer's default transport.

## Order and rollback

1. Record the live process pins below and the exact managed Tunnel snapshot.
   Confirm port 8871 is still free and the old relay has no pending job.
2. Install the two inert unit files and run `systemd-analyze verify` on them.
   Do not start the socket yet.
3. Apply the narrow native route and hostname 404 fallback. Wait for the
   existing Tunnel process to accept the new version. Keep private 18962
   routes first. Check that origin-only paths return 404.
4. Enable and start only `hivezilla-native-stream-proxy.socket`. This order
   prevents a broad public route from reaching the private origin.
5. Check missing, wrong and legacy keys return 401; check current-key head,
   exact-cursor beam headers and finite chunk reads. Compare source, cursor,
   frame and object hashes in RAM. Check all protected process pins and an
   existing private getBlock read. Save metadata and digests only.

For rollback, stop and disable the new socket and stop its bridge service
before restoring the exact old Tunnel snapshot. This avoids restoring a broad
fallback while the bridge can still reach private origin routes. The restored
old route will again have the known 502 until a later repair. Leave the old
relay disabled. Remove only these two new unit files if required. No source,
key, cursor, socket ACL, data file or native process needs restoration.

## Read-only source pins

The [before snapshot](evidence/preflight.json) and acceptance record have the
same protected pins. Recheck them before a later change.

| Component | PID | Invocation |
| --- | ---: | --- |
| `hivezilla-validator.service` | 1304643 | `a1edd40e43404e8cb9c81a7caacfa1ee` |
| Processed worker, c173 generation | 2108523 | `f3d5b43e7c584fe7a7c35b0f5f04d544` |
| Bank worker, c173 generation | 2128693 | `b2618cdc3b3346c188afdbf5236e33c7` |
| Native origin, c173 generation | 2108530 | `66781175b34a418c88f084a4c402d3f2` |
| `hivezilla-tunnel.service` | 480183 | `9d1592d736864f2da945d0353189cbad` |
| Native controller | 2108510 | `db3a236e5060436982fdd5849b92207e` |
| `blockzilla-recent-get-block.service` | 2304452 | `f89111729a024762b536779dc304c128` |

All seven were active, with zero restarts. Generation:
`c1739ce6fcee61291f41548b1960aa27`. Native source session:
`000000000000000018ea5078fdda19df-13e843`.

Origin executable:
`ROOT/releases/native-direct-origin-20261122-dd65404a0759159e/hivezilla-stream`.
SHA-256:
`dd65404a0759159eaa895c42c10057291d683af56ef06ae7da64037fd8599d75`.

`ROOT` is `/home/ubuntu/live/hivezilla-validator-20260930`. The saved version-4
API snapshot is the rollback source. Version 5 changes only this hostname's
native routing and fallback. The native authority and all private rules stay
unchanged.
