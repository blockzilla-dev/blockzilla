# Zillastream relay

Retain and deliver the original Compact V2 frames with source identity,
cursors, fork controls and explicit expiry. The existing `hivezilla-stream`
package and executable names are preserved.

```sh
cargo run --manifest-path zillastream/relay/Cargo.toml -- --help
cargo test --manifest-path zillastream/relay/Cargo.toml
```

The JavaScript SDK is under `client/`; the Rust decoder is under `decoder/`.
A relay uses bounded storage and client queues. A slow reader must reconnect
from a retained cursor or receive an explicit gap. It must not change source
identity or silently substitute a new head.

Object-store publication, application hooks and event-consumer services are
separate from the relay. See the client documentation for the delivery contract.
