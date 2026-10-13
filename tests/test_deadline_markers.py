def test_deadline_tight_marker_set(deadline_tight_nodeids: frozenset[str]) -> None:
    assert deadline_tight_nodeids == {
        "tests/test_review.py::test_sync_read_phase_cannot_outlive_remaining_whole_deadline[tight]",
        "tests/test_sync_session.py::test_sync_short_waiter_fixed_deadline_does_not_cancel_producer",
        "tests/test_sync_session.py::test_sync_expired_flight_retains_producer_and_discards_late_success",
        "tests/test_sync_transport.py::test_sync_repeated_reads_keep_one_deadline[tight-headers]",
        "tests/test_sync_transport.py::test_sync_repeated_reads_keep_one_deadline[tight-informational]",
        "tests/test_sync_transport.py::test_sync_repeated_reads_keep_one_deadline[tight-chunks]",
        "tests/test_sync_transport.py::test_sync_repeated_reads_keep_one_deadline[tight-chunk_metadata]",
        "tests/test_sync_transport.py::test_sync_tls_handshake_deadline",
        "tests/test_sync_transport.py::test_sync_pool_admission_deadline",
        "tests/test_sync_transport.py::test_sync_partial_writes_keep_one_deadline",
        "tests/test_sync_transport.py::test_sync_each_failed_address_uses_remaining_budget",
    }
