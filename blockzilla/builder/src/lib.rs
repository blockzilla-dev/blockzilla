//! Native compact-block workers consuming Zillastream's Agave capture journal.
pub mod confirmed;
pub mod consensus;
pub mod processed;
pub mod worker;

// Preserve the worker API while capture ownership moves to Zillastream.
pub use zillastream_capture_core::{event, journal, retention, source_retention};
