//! Queue-CBL — Valkey-like stream and pub/sub message broker primitives.
//!
//! Provides the data structures, IPC op-codes, and `QueueManager` that back
//! the `queue-cbl` crucible service.  All types are `no_std`-compatible;
//! actual I/O and scheduling are left to the integrating OS layer.
//!
//! # IPC Op-Codes
//!
//! | OpCode | Value | Signature |
//! |--------|-------|-----------|
//! | `StreamAppend`    | 500 | `(stream_name, data) → entry_id` |
//! | `StreamRead`      | 501 | `(stream_name, start_id, count) → Vec<StreamEntry>` |
//! | `StreamReadBlock` | 502 | `(stream_name, start_id, timeout_ms) → Vec<StreamEntry>` |
//! | `StreamAck`       | 503 | `(stream_name, group_name, entry_id) → ()` |
//! | `StreamPending`   | 504 | `(stream_name, group_name) → Vec<PendingEntry>` |
//! | `GroupCreate`     | 510 | `(stream_name, group_name, start_id) → ()` |
//! | `GroupClaim`      | 511 | `(stream_name, group_name, consumer, entry_id) → ()` |
//! | `PubSub`          | 520 | `(topic_name, message_data) → subscriber_count` |
//! | `Subscribe`       | 521 | `(topic_name) → subscription_id` |
//! | `Unsubscribe`     | 522 | `(subscription_id) → ()` |
//! | `StreamTrim`      | 530 | `(stream_name, max_len) → trimmed_count` |
//! | `StreamInfo`      | 531 | `(stream_name) → StreamInfo` |
//! | `StreamDelete`    | 532 | `(stream_name) → ()` |
//!
//! # Example
//!
//! ```
//! use temper::queue::{QueueManager, BackpressurePolicy};
//!
//! let mut qm = QueueManager::new();
//!
//! // Create a stream and append some entries
//! qm.create_stream("events", None).unwrap();
//! let id1 = qm.stream_append("events", b"hello".to_vec(), 1_000_000).unwrap();
//! let id2 = qm.stream_append("events", b"world".to_vec(), 2_000_000).unwrap();
//! assert!(id2 > id1);
//!
//! // Read them back
//! let entries = qm.stream_read("events", 1, 10).unwrap();
//! assert_eq!(entries.len(), 2);
//!
//! // Consumer group
//! qm.group_create("events", "grp", 1).unwrap();
//! let delivered = qm.stream_deliver("events", "grp", "consumer-1", 10, 3_000_000).unwrap();
//! assert_eq!(delivered.len(), 2);
//! qm.stream_ack("events", "grp", id1).unwrap();
//! let pending = qm.stream_pending("events", "grp").unwrap();
//! assert_eq!(pending.len(), 1);
//! ```

// Memory: import pattern per rust-nostd.instructions.md — alloc::* for heap types
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// region:    --- Modules

pub mod persistence;
pub mod pubsub;
pub mod streams;

// endregion: --- Modules

// region:    --- Re-exports

pub use persistence::{PersistError, PersistenceManager};
pub use pubsub::{PubSubError, PubSubManager, SubscriberInfo};
pub use streams::{
    ConsumerGroup, ConsumerState, PendingEntry, Stream, StreamEntry, StreamError, StreamInfo,
};

// endregion: --- Re-exports

// region:    --- IPC Op-Codes

/// IPC op-codes for the `queue-cbl` crucible service.
///
/// Op-codes 500–539 are reserved for the queue service.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueOp {
    /// Append an entry to a stream; returns the new entry ID.
    StreamAppend = 500,
    /// Read entries from a stream starting at a given ID.
    StreamRead = 501,
    /// Read entries, blocking until at least one is available.
    StreamReadBlock = 502,
    /// Acknowledge that a consumer group has processed an entry.
    StreamAck = 503,
    /// List pending (delivered-but-not-ACK'd) entries in a consumer group.
    StreamPending = 504,
    /// Create a consumer group on a stream.
    GroupCreate = 510,
    /// Claim a pending entry on behalf of a different consumer.
    GroupClaim = 511,
    /// Publish a message to a topic; returns subscriber count.
    PubSub = 520,
    /// Subscribe to a topic; returns subscription ID.
    Subscribe = 521,
    /// Unsubscribe from a topic.
    Unsubscribe = 522,
    /// Trim a stream to at most `max_len` entries.
    StreamTrim = 530,
    /// Query stream metadata.
    StreamInfo = 531,
    /// Delete an entire stream.
    StreamDelete = 532,
}

// endregion: --- IPC Op-Codes

// region:    --- Backpressure

/// Policy applied when a stream is at capacity and new entries arrive.
///
/// The policy is evaluated before each [`QueueManager::stream_append`] call
/// when the stream has a `max_len` set and that limit is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressurePolicy {
    /// Block the producer until space is available (not directly implementable
    /// in a no_std library; signals to the IPC layer to retry).
    Block,
    /// Silently drop the oldest entry to make room for the new one.
    DropOldest,
    /// Reject the new entry with an error.
    RejectError,
}

// endregion: --- Backpressure

// region:    --- QueueManager Errors

/// Top-level error type returned by all [`QueueManager`] operations.
///
/// Wraps lower-level errors from streams, pub/sub, and persistence with
/// additional context (e.g. the stream name that was not found).
#[derive(Debug)]
pub enum QueueError {
    /// No stream with this name exists.
    StreamNotFound(String),
    /// A stream with this name already exists.
    StreamAlreadyExists(String),
    /// Stream-level error (e.g. group or entry not found).
    Stream(StreamError),
    /// Pub/sub error (e.g. subscription not found).
    PubSub(PubSubError),
    /// Persistence error.
    Persist(PersistError),
    /// Producer was rejected due to backpressure policy.
    Backpressure(String),
}

impl From<StreamError> for QueueError {
    fn from(e: StreamError) -> Self {
        QueueError::Stream(e)
    }
}

impl From<PubSubError> for QueueError {
    fn from(e: PubSubError) -> Self {
        QueueError::PubSub(e)
    }
}

impl From<PersistError> for QueueError {
    fn from(e: PersistError) -> Self {
        QueueError::Persist(e)
    }
}

// endregion: --- QueueManager Errors

// region:    --- QueueManager

/// Top-level manager that owns all streams, the pub/sub system, and
/// the persistence helper.
///
/// This is a pure in-memory data structure; the OS integration layer is
/// responsible for calling [`PersistenceManager::serialize_stream`] to flush
/// state to durable storage.
#[derive(Debug)]
pub struct QueueManager {
    // Memory: BTreeMap for determinism per rust-nostd.instructions.md
    streams: BTreeMap<String, Stream>,
    pubsub: PubSubManager,
    persistence: PersistenceManager,
    /// Per-stream backpressure policies.
    backpressure: BTreeMap<String, BackpressurePolicy>,
}

// endregion: --- QueueManager

// region:    --- QueueManager Implementation

impl QueueManager {
    /// Create a new, empty `QueueManager` with default flush interval (1 024).
    pub fn new() -> Self {
        QueueManager {
            streams: BTreeMap::new(),
            pubsub: PubSubManager::new(),
            persistence: PersistenceManager::default(),
            backpressure: BTreeMap::new(),
        }
    }

    /// Create a new `QueueManager` with a custom persistence flush interval.
    pub fn with_flush_interval(flush_interval: usize) -> Self {
        QueueManager {
            streams: BTreeMap::new(),
            pubsub: PubSubManager::new(),
            persistence: PersistenceManager::new(flush_interval),
            backpressure: BTreeMap::new(),
        }
    }

    // region:    --- Stream Operations

    /// Create a new stream.
    ///
    /// `max_len` sets a hard cap; `None` means unbounded.
    pub fn create_stream(
        &mut self,
        name: &str,
        max_len: Option<usize>,
    ) -> Result<(), QueueError> {
        if self.streams.contains_key(name) {
            return Err(QueueError::StreamAlreadyExists(name.into()));
        }
        let stream = match max_len {
            Some(len) => Stream::with_max_len(name, len),
            None => Stream::new(name),
        };
        self.streams.insert(name.into(), stream);
        Ok(())
    }

    /// Append `data` to stream `name`.
    ///
    /// Returns the new entry's monotonic ID, or a [`QueueError`] if the stream
    /// does not exist or the backpressure policy rejects the append.
    pub fn stream_append(
        &mut self,
        name: &str,
        data: Vec<u8>,
        timestamp_ns: u64,
    ) -> Result<u64, QueueError> {
        let policy = self
            .backpressure
            .get(name)
            .copied()
            .unwrap_or(BackpressurePolicy::DropOldest);

        let stream = self
            .streams
            .get_mut(name)
            .ok_or_else(|| QueueError::StreamNotFound(name.into()))?;

        // Enforce backpressure when a max_len is set and reached.
        if let Some(max) = stream.max_len {
            if stream.entries.len() >= max {
                match policy {
                    BackpressurePolicy::RejectError => {
                        return Err(QueueError::Backpressure(name.into()));
                    }
                    BackpressurePolicy::Block => {
                        // Signal to caller that they should retry.
                        return Err(QueueError::Backpressure(name.into()));
                    }
                    BackpressurePolicy::DropOldest => {
                        // trim() inside append() handles this automatically.
                    }
                }
            }
        }

        let id = stream.append(data, timestamp_ns);
        self.persistence.mark_dirty(name);
        Ok(id)
    }

    /// Read up to `count` entries from stream `name` starting at `start_id`.
    pub fn stream_read(
        &self,
        name: &str,
        start_id: u64,
        count: usize,
    ) -> Result<Vec<StreamEntry>, QueueError> {
        let stream = self
            .streams
            .get(name)
            .ok_or_else(|| QueueError::StreamNotFound(name.into()))?;
        Ok(stream.read(start_id, count))
    }

    /// Deliver up to `count` new entries from stream `name` to `consumer` in `group`.
    pub fn stream_deliver(
        &mut self,
        stream_name: &str,
        group_name: &str,
        consumer: &str,
        count: usize,
        timestamp_ns: u64,
    ) -> Result<Vec<StreamEntry>, QueueError> {
        let stream = self
            .streams
            .get_mut(stream_name)
            .ok_or_else(|| QueueError::StreamNotFound(stream_name.into()))?;
        Ok(stream.deliver(group_name, consumer, count, timestamp_ns)?)
    }

    /// Acknowledge entry `entry_id` in consumer group `group_name` on stream `stream_name`.
    pub fn stream_ack(
        &mut self,
        stream_name: &str,
        group_name: &str,
        entry_id: u64,
    ) -> Result<(), QueueError> {
        let stream = self
            .streams
            .get_mut(stream_name)
            .ok_or_else(|| QueueError::StreamNotFound(stream_name.into()))?;
        Ok(stream.ack(group_name, entry_id)?)
    }

    /// List pending entries in `group_name` on stream `stream_name`.
    pub fn stream_pending(
        &self,
        stream_name: &str,
        group_name: &str,
    ) -> Result<Vec<PendingEntry>, QueueError> {
        let stream = self
            .streams
            .get(stream_name)
            .ok_or_else(|| QueueError::StreamNotFound(stream_name.into()))?;
        Ok(stream.pending_entries(group_name)?)
    }

    /// Create a consumer group on stream `stream_name`.
    pub fn group_create(
        &mut self,
        stream_name: &str,
        group_name: &str,
        start_id: u64,
    ) -> Result<(), QueueError> {
        let stream = self
            .streams
            .get_mut(stream_name)
            .ok_or_else(|| QueueError::StreamNotFound(stream_name.into()))?;
        Ok(stream.create_group(group_name, start_id)?)
    }

    /// Claim pending entry `entry_id` in `group_name` for `new_consumer`.
    pub fn group_claim(
        &mut self,
        stream_name: &str,
        group_name: &str,
        new_consumer: &str,
        entry_id: u64,
        timestamp_ns: u64,
    ) -> Result<(), QueueError> {
        let stream = self
            .streams
            .get_mut(stream_name)
            .ok_or_else(|| QueueError::StreamNotFound(stream_name.into()))?;
        Ok(stream.claim(group_name, new_consumer, entry_id, timestamp_ns)?)
    }

    /// Trim stream `name` to at most `max_len` entries.
    ///
    /// Returns the number of entries removed.
    pub fn stream_trim(&mut self, name: &str, max_len: usize) -> Result<usize, QueueError> {
        let stream = self
            .streams
            .get_mut(name)
            .ok_or_else(|| QueueError::StreamNotFound(name.into()))?;
        Ok(stream.trim(max_len))
    }

    /// Return summary information about stream `name`.
    pub fn stream_info(&self, name: &str) -> Result<StreamInfo, QueueError> {
        let stream = self
            .streams
            .get(name)
            .ok_or_else(|| QueueError::StreamNotFound(name.into()))?;
        Ok(stream.info())
    }

    /// Delete stream `name`.
    pub fn stream_delete(&mut self, name: &str) -> Result<(), QueueError> {
        if self.streams.remove(name).is_none() {
            return Err(QueueError::StreamNotFound(name.into()));
        }
        Ok(())
    }

    /// Set the backpressure policy for stream `name`.
    pub fn set_backpressure(&mut self, name: &str, policy: BackpressurePolicy) {
        self.backpressure.insert(name.into(), policy);
    }

    // endregion: --- Stream Operations

    // region:    --- Pub/Sub Operations

    /// Subscribe `client_id` to `topic`, returning the subscription ID.
    pub fn subscribe(&mut self, topic: &str, client_id: u64) -> u64 {
        self.pubsub.subscribe(topic, client_id)
    }

    /// Unsubscribe the subscription `sub_id`.
    pub fn unsubscribe(&mut self, sub_id: u64) -> Result<(), QueueError> {
        Ok(self.pubsub.unsubscribe(sub_id)?)
    }

    /// Publish to `topic`.
    ///
    /// Returns the list of `client_id`s that should receive the message.
    /// The caller delivers the message to each client.
    pub fn publish(&self, topic: &str) -> Vec<u64> {
        self.pubsub.publish(topic)
    }

    /// Return the subscriber count for `topic`.
    pub fn subscriber_count(&self, topic: &str) -> usize {
        self.pubsub.subscriber_count(topic)
    }

    // endregion: --- Pub/Sub Operations

    // region:    --- Persistence Operations

    /// Return `true` when a persistence flush should be triggered.
    pub fn should_flush(&self) -> bool {
        self.persistence.should_flush()
    }

    /// Return the names of streams modified since the last flush.
    pub fn dirty_stream_names(&self) -> Vec<String> {
        self.persistence.dirty_stream_names()
    }

    /// Signal that a flush has completed; resets the dirty tracking state.
    pub fn flush_complete(&mut self) {
        self.persistence.flush_complete();
    }

    /// Serialise stream `name` to `postcard` bytes for durable storage.
    ///
    /// Returns `Err` if the stream does not exist or serialisation fails.
    pub fn serialize_stream(&self, name: &str) -> Result<Vec<u8>, QueueError> {
        let stream = self
            .streams
            .get(name)
            .ok_or_else(|| QueueError::StreamNotFound(name.into()))?;
        Ok(PersistenceManager::serialize_stream(stream)?)
    }

    /// Deserialise a stream from `postcard` bytes and register it.
    ///
    /// Overwrites any existing stream with the same name.
    pub fn restore_stream(&mut self, data: &[u8]) -> Result<String, QueueError> {
        let stream = PersistenceManager::deserialize_stream(data)?;
        let name = stream.name.clone();
        self.streams.insert(name.clone(), stream);
        Ok(name)
    }

    // endregion: --- Persistence Operations
}

impl Default for QueueManager {
    fn default() -> Self {
        Self::new()
    }
}

// endregion: --- QueueManager Implementation
