//! Pub/sub topic management for queue-cbl.
//!
//! Implements a fan-out publish/subscribe system. Publishers post messages to
//! named topics and receive the set of subscriber client IDs to notify.
//! Actual message delivery (IPC or in-process) is left to the caller.

// Memory: import pattern per rust-nostd.instructions.md — alloc::* for heap types
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// region:    --- Pub/Sub Types

/// Information about a single subscriber.
#[derive(Debug, Clone)]
pub struct SubscriberInfo {
    /// Unique subscription ID assigned at subscribe time.
    pub id: u64,
    /// Opaque client identifier (e.g. process ID, connection handle).
    pub client_id: u64,
}

/// A named pub/sub topic with its list of current subscribers.
#[derive(Debug, Clone)]
pub struct Topic {
    /// Ordered list of active subscribers.
    // Memory: Vec is fine here; ordering matches subscription order
    pub(crate) subscribers: Vec<SubscriberInfo>,
}

/// Manages pub/sub topics and their subscribers.
///
/// Topic names are arbitrary strings. Subscription IDs are unique across all
/// topics managed by a single `PubSubManager`.
#[derive(Debug, Clone)]
pub struct PubSubManager {
    // Memory: BTreeMap for determinism per rust-nostd.instructions.md
    topics: BTreeMap<String, Topic>,
    /// Global subscription ID counter, monotonically increasing.
    next_sub_id: u64,
}

// endregion: --- Pub/Sub Types

// region:    --- Pub/Sub Errors

/// Errors returned by [`PubSubManager`] operations.
#[derive(Debug)]
pub enum PubSubError {
    /// No subscription with this ID was found.
    SubscriptionNotFound(u64),
}

// endregion: --- Pub/Sub Errors

// region:    --- PubSubManager Implementation

impl PubSubManager {
    /// Create a new, empty `PubSubManager`.
    pub fn new() -> Self {
        PubSubManager {
            topics: BTreeMap::new(),
            next_sub_id: 1,
        }
    }

    /// Subscribe `client_id` to `topic`, returning the new subscription ID.
    ///
    /// Creates the topic automatically if it does not yet exist.
    pub fn subscribe(&mut self, topic: &str, client_id: u64) -> u64 {
        let sub_id = self.next_sub_id;
        self.next_sub_id += 1;

        let entry = self.topics.entry(topic.into()).or_insert_with(|| Topic {
            subscribers: Vec::new(),
        });
        entry.subscribers.push(SubscriberInfo { id: sub_id, client_id });

        sub_id
    }

    /// Unsubscribe the subscription identified by `sub_id`.
    ///
    /// Removes the subscriber from whichever topic holds it.
    pub fn unsubscribe(&mut self, sub_id: u64) -> Result<(), PubSubError> {
        for topic in self.topics.values_mut() {
            let before = topic.subscribers.len();
            topic.subscribers.retain(|s| s.id != sub_id);
            if topic.subscribers.len() < before {
                return Ok(());
            }
        }
        Err(PubSubError::SubscriptionNotFound(sub_id))
    }

    /// Publish `message` to `topic`.
    ///
    /// Returns the list of `client_id`s that should receive the message.
    /// The caller is responsible for actually delivering the message to each
    /// client (e.g. via IPC).
    pub fn publish(&self, topic: &str) -> Vec<u64> {
        match self.topics.get(topic) {
            Some(t) => t.subscribers.iter().map(|s| s.client_id).collect(),
            None => Vec::new(),
        }
    }

    /// Return the number of subscribers on `topic`.
    pub fn subscriber_count(&self, topic: &str) -> usize {
        self.topics
            .get(topic)
            .map(|t| t.subscribers.len())
            .unwrap_or(0)
    }

    /// Return all topic names currently managed.
    pub fn topic_names(&self) -> Vec<String> {
        self.topics.keys().cloned().collect()
    }
}

impl Default for PubSubManager {
    fn default() -> Self {
        Self::new()
    }
}

// endregion: --- PubSubManager Implementation
