//! Persistence helpers for queue-cbl stream state.
//!
//! Serialises and deserialises [`Stream`] structs using `postcard` so that the
//! caller can persist them to storage (e.g. LedgerFS) and recover them on boot.
//!
//! The persistence manager tracks which streams have been modified since the
//! last flush and can advise when a flush is due.

// Memory: import pattern per rust-nostd.instructions.md — alloc::* for heap types
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::queue::streams::Stream;

// region:    --- Persistence Errors

/// Errors returned by [`PersistenceManager`] serialisation and deserialisation operations.
#[derive(Debug)]
pub enum PersistError {
    /// Serialisation into bytes failed.
    SerializeError(String),
    /// Deserialisation from bytes failed.
    DeserializeError(String),
}

// endregion: --- Persistence Errors

// region:    --- PersistenceManager

/// Tracks dirty streams and serialises/deserialises stream state.
///
/// Actual I/O (file writes, network calls, etc.) is the caller's responsibility.
/// This type provides the serialised bytes and the flush schedule; the integration
/// layer decides *where* and *when* to write them.
#[derive(Debug)]
pub struct PersistenceManager {
    /// Flush is triggered after this many appends.
    flush_interval: usize,
    /// Set of stream names that have been modified since the last flush.
    // Memory: BTreeSet for determinism per rust-nostd.instructions.md
    dirty_streams: BTreeSet<String>,
    /// Running counter of appends since the last flush.
    append_count: usize,
}

// endregion: --- PersistenceManager

// region:    --- PersistenceManager Implementation

impl PersistenceManager {
    /// Create a new `PersistenceManager` with the given flush interval.
    ///
    /// `flush_interval` is the number of stream appends after which
    /// [`should_flush`](Self::should_flush) returns `true`.
    pub fn new(flush_interval: usize) -> Self {
        PersistenceManager {
            flush_interval,
            dirty_streams: BTreeSet::new(),
            append_count: 0,
        }
    }

    /// Notify the manager that `stream_name` has been modified.
    ///
    /// Also increments the internal append counter used to decide when to flush.
    pub fn mark_dirty(&mut self, stream_name: &str) {
        self.dirty_streams.insert(stream_name.into());
        self.append_count += 1;
    }

    /// Returns `true` when a flush is due (append count ≥ flush interval).
    pub fn should_flush(&self) -> bool {
        self.flush_interval > 0 && self.append_count >= self.flush_interval
    }

    /// Reset the flush counter and clear the dirty set after a successful flush.
    pub fn flush_complete(&mut self) {
        self.append_count = 0;
        self.dirty_streams.clear();
    }

    /// Return the names of all streams that have been modified since the last flush.
    pub fn dirty_stream_names(&self) -> Vec<String> {
        self.dirty_streams.iter().cloned().collect()
    }

    /// Serialise `stream` into a `postcard`-encoded byte vector.
    ///
    /// The resulting bytes can be written to storage at a path such as
    /// `/queue-cbl/streams/{stream_name}/state`.
    pub fn serialize_stream(stream: &Stream) -> Result<Vec<u8>, PersistError> {
        postcard::to_allocvec(stream).map_err(|e| {
            PersistError::SerializeError(alloc::format!("{:?}", e))
        })
    }

    /// Deserialise a `Stream` from `postcard`-encoded `data`.
    ///
    /// Call this on boot for each persisted stream file to recover state.
    pub fn deserialize_stream(data: &[u8]) -> Result<Stream, PersistError> {
        postcard::from_bytes(data).map_err(|e| {
            PersistError::DeserializeError(alloc::format!("{:?}", e))
        })
    }
}

impl Default for PersistenceManager {
    fn default() -> Self {
        // Memory: re-seed pattern — default flush every 1024 appends
        Self::new(1024)
    }
}

// endregion: --- PersistenceManager Implementation
