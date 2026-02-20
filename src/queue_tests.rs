//! Tests for the queue-cbl stream, pub/sub, and persistence modules.
//!
//! Verifies correctness of stream ordering, consumer group delivery,
//! acknowledgement, claim, trim, pub/sub fan-out, and persistence round-trips.

#[cfg(test)]
mod tests {
    use crate::queue::{
        PersistenceManager, QueueManager,
    };

    // Tests run under the std test harness so std is available.
    #[allow(unused_imports)]
    use std::println;

    // region:    --- Stream Tests

    #[test]
    fn test_stream_append_read_monotonic() {
        // Property: 10 000 appended entries must be readable in strict
        //           monotonically-increasing ID order.

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        qm.create_stream("events", None).expect("create stream");
        let n = 10_000usize;

        // -- Exec
        let mut ids = std::vec::Vec::with_capacity(n);
        for i in 0..n {
            let id = qm
                .stream_append("events", std::vec![i as u8], i as u64)
                .expect("append");
            ids.push(id);
        }

        let entries = qm.stream_read("events", 1, n).expect("read");

        // -- Check
        assert_eq!(entries.len(), n, "Expected {} entries", n);

        // IDs must be strictly increasing
        let mut prev = 0u64;
        for e in &entries {
            assert!(
                e.id > prev,
                "Entry ID {} not strictly greater than previous {}",
                e.id,
                prev
            );
            prev = e.id;
        }

        // The IDs we received while appending should match the read-back IDs
        let read_ids: std::vec::Vec<u64> = entries.iter().map(|e| e.id).collect();
        assert_eq!(
            ids, read_ids,
            "Append-time IDs must match read-back IDs"
        );

        println!("Stream append/read: {} entries, IDs [{}, {}]", n, ids[0], ids[n - 1]);
    }

    #[test]
    fn test_consumer_group_unique_delivery_and_ack() {
        // Property: three consumers in the same group each receive a disjoint
        //           subset of entries; ACK removes entries from the pending list.

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        qm.create_stream("work", None).expect("create stream");

        let total = 9usize;
        for i in 0..total {
            qm.stream_append("work", std::vec![i as u8], i as u64)
                .expect("append");
        }

        qm.group_create("work", "grp", 1).expect("create group");

        // -- Exec: each consumer fetches 3 entries
        let d1 = qm
            .stream_deliver("work", "grp", "c1", 3, 100)
            .expect("deliver c1");
        let d2 = qm
            .stream_deliver("work", "grp", "c2", 3, 200)
            .expect("deliver c2");
        let d3 = qm
            .stream_deliver("work", "grp", "c3", 3, 300)
            .expect("deliver c3");

        // -- Check: each consumer gets exactly 3, no overlaps
        assert_eq!(d1.len(), 3, "c1 should receive 3 entries");
        assert_eq!(d2.len(), 3, "c2 should receive 3 entries");
        assert_eq!(d3.len(), 3, "c3 should receive 3 entries");

        let ids1: std::collections::HashSet<u64> = d1.iter().map(|e| e.id).collect();
        let ids2: std::collections::HashSet<u64> = d2.iter().map(|e| e.id).collect();
        let ids3: std::collections::HashSet<u64> = d3.iter().map(|e| e.id).collect();
        assert!(ids1.is_disjoint(&ids2), "c1 and c2 entries must not overlap");
        assert!(ids1.is_disjoint(&ids3), "c1 and c3 entries must not overlap");
        assert!(ids2.is_disjoint(&ids3), "c2 and c3 entries must not overlap");

        // ACK all entries from c1
        for e in &d1 {
            qm.stream_ack("work", "grp", e.id).expect("ack");
        }

        let pending = qm.stream_pending("work", "grp").expect("pending");
        assert_eq!(
            pending.len(),
            6,
            "After ACKing 3 of 9 entries, 6 should remain pending"
        );

        println!(
            "Consumer group: d1={}, d2={}, d3={}, pending after ACK={}",
            d1.len(),
            d2.len(),
            d3.len(),
            pending.len()
        );
    }

    #[test]
    fn test_stream_pending_shows_unacked_entries() {
        // Property: XPENDING returns exactly the entries that were delivered
        //           but not yet acknowledged.

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        qm.create_stream("tasks", None).expect("create stream");

        let ids: std::vec::Vec<u64> = (0..5u64)
            .map(|i| qm.stream_append("tasks", std::vec![0u8], i).expect("append"))
            .collect();

        qm.group_create("tasks", "workers", 1).expect("create group");
        qm.stream_deliver("tasks", "workers", "w1", 5, 1000)
            .expect("deliver");

        // ACK only the first entry
        qm.stream_ack("tasks", "workers", ids[0]).expect("ack");

        // -- Exec
        let pending = qm.stream_pending("tasks", "workers").expect("pending");

        // -- Check
        assert_eq!(
            pending.len(),
            4,
            "4 of 5 entries should remain pending; got {}",
            pending.len()
        );

        let pending_ids: std::collections::HashSet<u64> =
            pending.iter().map(|p| p.entry_id).collect();
        assert!(
            !pending_ids.contains(&ids[0]),
            "ACK'd entry must not appear in pending"
        );
        for &id in &ids[1..] {
            assert!(
                pending_ids.contains(&id),
                "Unacknowledged entry {} must appear in pending",
                id
            );
        }

        println!("XPENDING: {} un-ACK'd entries", pending.len());
    }

    #[test]
    fn test_group_claim_transfers_pending_entry() {
        // Property: XCLAIM transfers a pending entry to a different consumer.

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        qm.create_stream("jobs", None).expect("create stream");
        let id = qm.stream_append("jobs", b"payload".to_vec(), 1000).expect("append");
        qm.group_create("jobs", "grp", 1).expect("create group");
        qm.stream_deliver("jobs", "grp", "worker-A", 1, 1000)
            .expect("deliver");

        // -- Exec: worker-B claims the entry from worker-A
        qm.group_claim("jobs", "grp", "worker-B", id, 2000)
            .expect("claim");

        // -- Check: the entry is now owned by worker-B
        let pending = qm.stream_pending("jobs", "grp").expect("pending");
        assert_eq!(pending.len(), 1, "Entry should still be pending after claim");
        assert_eq!(
            pending[0].consumer, "worker-B",
            "Entry should be owned by worker-B after claim"
        );
        assert_eq!(
            pending[0].delivery_count, 2,
            "Delivery count should increment on claim"
        );

        println!("XCLAIM: entry {} transferred to {}", id, pending[0].consumer);
    }

    #[test]
    fn test_stream_maxlen_trim_oldest() {
        // Property: appending 200 entries with max_len=100 trims the oldest 100.

        // -- Setup & Fixtures
        let max_len = 100usize;
        let total = 200usize;
        let mut qm = QueueManager::new();
        qm.create_stream("trimmed", Some(max_len)).expect("create stream");

        // -- Exec
        let mut all_ids = std::vec::Vec::with_capacity(total);
        for i in 0..total {
            let id = qm
                .stream_append("trimmed", std::vec![i as u8], i as u64)
                .expect("append");
            all_ids.push(id);
        }

        let info = qm.stream_info("trimmed").expect("info");

        // -- Check
        assert_eq!(
            info.length, max_len,
            "Stream length should be at most max_len={}, got {}",
            max_len, info.length
        );
        // The oldest entries (IDs 1..=100) should be gone, newest (101..=200) remain
        let earliest_id = all_ids[total - max_len]; // first surviving ID
        assert_eq!(
            info.first_id, earliest_id,
            "First entry ID after trim should be {} (got {})",
            earliest_id, info.first_id
        );

        println!(
            "MAXLEN trim: {} entries appended, {} retained (IDs {}-{})",
            total, info.length, info.first_id, info.last_id
        );
    }

    #[test]
    fn test_stream_manual_trim() {
        // Property: explicit trim() removes the correct number of oldest entries.

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        qm.create_stream("log", None).expect("create stream");
        for i in 0..200u64 {
            qm.stream_append("log", std::vec![0u8], i).expect("append");
        }

        // -- Exec
        let trimmed = qm.stream_trim("log", 100).expect("trim");

        // -- Check
        assert_eq!(trimmed, 100, "Expected 100 entries trimmed, got {}", trimmed);
        let info = qm.stream_info("log").expect("info");
        assert_eq!(
            info.length, 100,
            "Stream should have 100 entries after trim"
        );

        println!("Manual trim: {} entries removed, {} remain", trimmed, info.length);
    }

    // endregion: --- Stream Tests

    // region:    --- Pub/Sub Tests

    #[test]
    fn test_pubsub_fan_out() {
        // Property: 1 publisher, 3 subscribers → all 3 receive every message.

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        let sub1 = qm.subscribe("alerts", 1001);
        let sub2 = qm.subscribe("alerts", 1002);
        let sub3 = qm.subscribe("alerts", 1003);

        // Suppress unused variable warnings; they may be used in future assertions.
        let _ = (sub1, sub2, sub3);

        // -- Exec
        let recipients = qm.publish("alerts");

        // -- Check
        assert_eq!(
            recipients.len(),
            3,
            "All 3 subscribers must be returned by publish"
        );

        let mut sorted = recipients.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            std::vec![1001u64, 1002, 1003],
            "Recipient client IDs must match the three subscribers"
        );

        println!(
            "Pub/sub fan-out: {} recipients for topic 'alerts'",
            recipients.len()
        );
    }

    #[test]
    fn test_pubsub_unsubscribe() {
        // Property: after unsubscribing, the client is no longer notified.

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        let sub1 = qm.subscribe("news", 2001);
        let _sub2 = qm.subscribe("news", 2002);

        // -- Exec
        qm.unsubscribe(sub1).expect("unsubscribe");
        let recipients = qm.publish("news");

        // -- Check
        assert_eq!(
            recipients.len(),
            1,
            "Only 1 subscriber should remain after unsubscribe"
        );
        assert_eq!(
            recipients[0], 2002,
            "Remaining subscriber should be client 2002"
        );

        println!(
            "Pub/sub unsubscribe: {} recipient(s) after removing sub {}",
            recipients.len(),
            sub1
        );
    }

    #[test]
    fn test_pubsub_no_subscribers() {
        // Property: publishing to a topic with no subscribers returns an empty list.

        // -- Setup & Fixtures
        let qm = QueueManager::new();

        // -- Exec
        let recipients = qm.publish("nonexistent-topic");

        // -- Check
        assert!(
            recipients.is_empty(),
            "Publishing to empty topic must return empty recipient list"
        );
    }

    // endregion: --- Pub/Sub Tests

    // region:    --- Persistence Tests

    #[test]
    fn test_persistence_serialize_deserialize_roundtrip() {
        // Property: a stream serialised to bytes and then deserialised must be
        //           identical to the original (same entries, groups, metadata).

        // -- Setup & Fixtures
        let mut qm = QueueManager::new();
        qm.create_stream("durable", None).expect("create stream");
        let id1 = qm
            .stream_append("durable", b"entry-one".to_vec(), 1_000_000)
            .expect("append 1");
        let id2 = qm
            .stream_append("durable", b"entry-two".to_vec(), 2_000_000)
            .expect("append 2");
        qm.group_create("durable", "consumers", 1).expect("create group");
        qm.stream_deliver("durable", "consumers", "worker", 1, 1_000_000)
            .expect("deliver");

        // -- Exec
        let bytes = qm.serialize_stream("durable").expect("serialize");
        let mut qm2 = QueueManager::new();
        let restored_name = qm2.restore_stream(&bytes).expect("restore");

        // -- Check
        assert_eq!(restored_name, "durable", "Restored stream name mismatch");

        let entries = qm2.stream_read("durable", 1, 10).expect("read");
        assert_eq!(entries.len(), 2, "Restored stream must have 2 entries");
        assert_eq!(entries[0].id, id1);
        assert_eq!(entries[1].id, id2);
        assert_eq!(entries[0].data, b"entry-one");
        assert_eq!(entries[1].data, b"entry-two");

        let pending = qm2
            .stream_pending("durable", "consumers")
            .expect("pending");
        assert_eq!(
            pending.len(),
            1,
            "Restored stream must still have 1 pending entry"
        );

        println!(
            "Persistence roundtrip: {} bytes, {} entries, {} pending",
            bytes.len(),
            entries.len(),
            pending.len()
        );
    }

    #[test]
    fn test_persistence_flush_tracking() {
        // Property: should_flush() returns true only after flush_interval appends;
        //           flush_complete() resets the counter.

        // -- Setup & Fixtures
        let interval = 5usize;
        let mut qm = QueueManager::with_flush_interval(interval);
        qm.create_stream("metrics", None).expect("create stream");

        // -- Exec / Check: not dirty yet
        assert!(!qm.should_flush(), "should_flush must be false before any appends");

        for i in 0..interval {
            qm.stream_append("metrics", std::vec![0u8], i as u64)
                .expect("append");
        }

        assert!(
            qm.should_flush(),
            "should_flush must be true after {} appends",
            interval
        );
        assert!(
            qm.dirty_stream_names().contains(&"metrics".into()),
            "metrics must appear in dirty stream names"
        );

        qm.flush_complete();
        assert!(!qm.should_flush(), "should_flush must be false after flush_complete");
        assert!(
            qm.dirty_stream_names().is_empty(),
            "dirty stream names must be empty after flush_complete"
        );

        println!(
            "Flush tracking: interval={}, dirty before flush={:?}",
            interval, true
        );
    }

    #[test]
    fn test_persistence_manager_serialize_deserialize() {
        // Property: PersistenceManager::serialize_stream and deserialize_stream
        //           produce a structurally identical stream.

        // -- Setup & Fixtures
        use crate::queue::streams::Stream;
        let mut stream = Stream::new("s1");
        stream.append(b"alpha".to_vec(), 1_000);
        stream.append(b"beta".to_vec(), 2_000);
        stream.create_group("g1", 1).expect("create group");

        // -- Exec
        let bytes = PersistenceManager::serialize_stream(&stream)
            .expect("serialize");
        let restored = PersistenceManager::deserialize_stream(&bytes)
            .expect("deserialize");

        // -- Check
        assert_eq!(restored.name, "s1");
        let entries = restored.read(1, 10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"alpha");
        assert_eq!(entries[1].data, b"beta");

        println!(
            "PersistenceManager roundtrip: {} bytes",
            bytes.len()
        );
    }

    // endregion: --- Persistence Tests
}
