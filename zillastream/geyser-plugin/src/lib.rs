//! Zillastream's native Geyser adapter for the matching patched Agave host.

pub use zillastream_capture_core::{event, journal};

mod plugin;
pub use plugin::{Plugin, transaction_event};

// The real compact-worker integration uses Linux filesystem mutation watches.
#[cfg(all(test, target_os = "linux"))]
mod epoch_engine;
