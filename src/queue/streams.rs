//! Stream data structures for queue-cbl.
//!
//! Implements Redis Streams-like data structures: append-only log entries,
//! consumer groups with at-least-once delivery, and monotonic entry IDs.

// Memory: import pattern per rust-nostd.instructions.md — alloc::* for heap types
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

// region:    --- Stream Types

/// A single entry in a stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEntry {
    /// Monotonic, unique ID for this entry.
    pub id: u64,
    /// Timestamp when this entry was appended (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Serialized entry payload.
    pub data: Vec<u8>,
}

/// State of a single consumer within a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerState {
    /// Consumer name.
    pub name: String,
    /// Timestamp of the consumer's last interaction (nanoseconds since epoch).
    pub last_seen: u64,
}

/// A pending (delivered but not yet ACK'd) entry within a consumer group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEntry {
    /// Entry ID.
    pub entry_id: u64,
    /// Consumer that holds this pending entry.
    pub consumer: String,
    /// Timestamp when this entry was first delivered (nanoseconds since epoch).
    pub delivered_at: u64,
    /// Number of times this entry has been delivered.
    pub delivery_count: u32,
}

/// A consumer group tracking delivery state over a stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerGroup {
    /// Group name.
    pub name: String,
    /// ID of the last entry delivered to any consumer in this group.
    pub last_delivered_id: u64,
    /// Map of consumer name → consumer state.
    // Memory: BTreeMap for determinism per rust-nostd.instructions.md
    pub consumers: BTreeMap<String, ConsumerState>,
    /// Map of entry_id → pending entry (delivered but not ACK'd).
    pub pending: BTreeMap<u64, PendingEntry>,
}

/// Summary information about a stream.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream name.
    pub name: String,
    /// Total number of entries currently in the stream.
    pub length: usize,
    /// Monotonic ID of the first entry (0 if empty).
    pub first_id: u64,
    /// Monotonic ID of the last entry (0 if empty).
    pub last_id: u64,
    /// Number of consumer groups.
    pub group_count: usize,
    /// Optional maximum length enforced on this stream.
    pub max_len: Option<usize>,
}

/// An append-only stream with consumer-group delivery tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    /// Stream name.
    pub name: String,
    /// Entries indexed by monotonic ID.
    // Memory: BTreeMap for determinism per rust-nostd.instructions.md
    pub(crate) entries: BTreeMap<u64, StreamEntry>,
    /// Next ID to assign on append.
    pub(crate) next_id: u64,
    /// Consumer groups.
    pub(crate) groups: BTreeMap<String, ConsumerGroup>,
    /// Optional maximum number of entries to retain.
    pub(crate) max_len: Option<usize>,
}

// endregion: --- Stream Types

// region:    --- Stream Errors

/// Errors returned by individual [`Stream`] operations.
#[derive(Debug)]
pub enum StreamError {
    /// The requested consumer group does not exist.
    GroupNotFound(String),
    /// A consumer group with this name already exists.
    GroupAlreadyExists(String),
    /// The requested entry ID does not exist.
    EntryNotFound(u64),
    /// The entry is not pending for this consumer.
    NotPending(u64),
}

// endregion: --- Stream Errors

// region:    --- Stream Implementation

impl Stream {
    /// Create a new empty stream with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Stream {
            name: name.into(),
            entries: BTreeMap::new(),
            next_id: 1,
            groups: BTreeMap::new(),
            max_len: None,
        }
    }

    /// Create a new stream with a configured maximum length.
    pub fn with_max_len(name: impl Into<String>, max_len: usize) -> Self {
        Stream {
            name: name.into(),
            entries: BTreeMap::new(),
            next_id: 1,
            groups: BTreeMap::new(),
            max_len: Some(max_len),
        }
    }

    /// Append an entry to the stream and return the new entry's ID.
    ///
    /// If `max_len` is configured, the oldest entries are trimmed automatically.
    pub fn append(&mut self, data: Vec<u8>, timestamp_ns: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        self.entries.insert(
            id,
            StreamEntry {
                id,
                timestamp_ns,
                data,
            },
        );

        if let Some(max) = self.max_len {
            self.trim_to(max);
        }

        id
    }

    /// Read up to `count` entries starting from `start_id` (inclusive).
    pub fn read(&self, start_id: u64, count: usize) -> Vec<StreamEntry> {
        self.entries
            .range(start_id..)
            .take(count)
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Deliver up to `count` undelivered entries to `consumer` in group `group_name`.
    ///
    /// Entries at or after `group.last_delivered_id + 1` are eligible.
    /// Each delivered entry is added to the group's pending list.
    pub fn deliver(
        &mut self,
        group_name: &str,
        consumer: &str,
        count: usize,
        timestamp_ns: u64,
    ) -> Result<Vec<StreamEntry>, StreamError> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| StreamError::GroupNotFound(group_name.into()))?;

        let start_id = group.last_delivered_id + 1;
        let deliverable: Vec<StreamEntry> = self
            .entries
            .range(start_id..)
            .take(count)
            .map(|(_, e)| e.clone())
            .collect();

        for entry in &deliverable {
            group.last_delivered_id = entry.id;
            group.pending.insert(
                entry.id,
                PendingEntry {
                    entry_id: entry.id,
                    consumer: consumer.into(),
                    delivered_at: timestamp_ns,
                    delivery_count: 1,
                },
            );
            group.consumers.insert(
                consumer.into(),
                ConsumerState {
                    name: consumer.into(),
                    last_seen: timestamp_ns,
                },
            );
        }

        Ok(deliverable)
    }

    /// Acknowledge that `consumer` in `group_name` has processed `entry_id`.
    pub fn ack(&mut self, group_name: &str, entry_id: u64) -> Result<(), StreamError> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| StreamError::GroupNotFound(group_name.into()))?;

        if group.pending.remove(&entry_id).is_none() {
            return Err(StreamError::NotPending(entry_id));
        }

        Ok(())
    }

    /// Return all pending entries in `group_name`.
    pub fn pending_entries(&self, group_name: &str) -> Result<Vec<PendingEntry>, StreamError> {
        let group = self
            .groups
            .get(group_name)
            .ok_or_else(|| StreamError::GroupNotFound(group_name.into()))?;

        Ok(group.pending.values().cloned().collect())
    }

    /// Create a consumer group starting at `start_id`.
    ///
    /// If `start_id` is 0, the group will start at the beginning of the stream.
    pub fn create_group(&mut self, name: impl Into<String>, start_id: u64) -> Result<(), StreamError> {
        let name = name.into();
        if self.groups.contains_key(&name) {
            return Err(StreamError::GroupAlreadyExists(name));
        }
        // last_delivered_id starts just before start_id so the first deliver
        // returns entries >= start_id.
        let last_delivered_id = if start_id == 0 { 0 } else { start_id - 1 };
        self.groups.insert(
            name.clone(),
            ConsumerGroup {
                name,
                last_delivered_id,
                consumers: BTreeMap::new(),
                pending: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Transfer ownership of a pending entry in `group_name` to `new_consumer`.
    pub fn claim(
        &mut self,
        group_name: &str,
        new_consumer: &str,
        entry_id: u64,
        timestamp_ns: u64,
    ) -> Result<(), StreamError> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| StreamError::GroupNotFound(group_name.into()))?;

        let entry = group
            .pending
            .get_mut(&entry_id)
            .ok_or(StreamError::NotPending(entry_id))?;

        entry.consumer = new_consumer.into();
        entry.delivered_at = timestamp_ns;
        entry.delivery_count += 1;

        group.consumers.insert(
            new_consumer.into(),
            ConsumerState {
                name: new_consumer.into(),
                last_seen: timestamp_ns,
            },
        );

        Ok(())
    }

    /// Trim the stream to at most `max_len` entries, removing the oldest.
    ///
    /// Returns the number of entries removed.
    pub fn trim(&mut self, max_len: usize) -> usize {
        self.trim_to(max_len)
    }

    /// Return summary information about this stream.
    pub fn info(&self) -> StreamInfo {
        let first_id = self.entries.keys().next().copied().unwrap_or(0);
        let last_id = self.entries.keys().next_back().copied().unwrap_or(0);
        StreamInfo {
            name: self.name.clone(),
            length: self.entries.len(),
            first_id,
            last_id,
            group_count: self.groups.len(),
            max_len: self.max_len,
        }
    }

    /// Internal helper: trim to at most `max_len`, return removed count.
    fn trim_to(&mut self, max_len: usize) -> usize {
        let excess = self.entries.len().saturating_sub(max_len);
        if excess == 0 {
            return 0;
        }
        // Collect keys of oldest entries
        let to_remove: Vec<u64> = self.entries.keys().take(excess).copied().collect();
        for key in &to_remove {
            self.entries.remove(key);
        }
        to_remove.len()
    }
}

// endregion: --- Stream Implementation
