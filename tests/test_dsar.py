from privacy_platform.dsar import DataStore, DSARService

RECORDS = [
    {"subject_id": "cust-001", "email": "a@example.com", "created_at": "2023-01-15"},
    {"subject_id": "cust-001", "email": "a2@example.com", "created_at": "2023-02-15"},
    {"subject_id": "cust-002", "email": "b@example.com", "created_at": "2024-01-15"},
]


def _service():
    store = DataStore()
    store.add_dataset("customers", RECORDS)
    store.add_dataset("orders", [{"subject_id": "cust-001", "total": 42}])
    return store, DSARService(store, downstream_map={
        "customers": ["analytics_warehouse", "crm"],
        "orders": ["analytics_warehouse"],
    })


def test_access_export_returns_only_the_subjects_records():
    store, service = _service()
    export = service.access("cust-001")
    assert len(export["customers"]) == 2
    assert len(export["orders"]) == 1
    assert service.access("cust-999") == {}


def test_erasure_removes_records_leaves_tombstones_and_reports_propagation():
    store, service = _service()
    report = service.erase("cust-001")
    assert report.datasets_erased == {"customers": 2, "orders": 1}
    assert len(report.tombstones) == 3
    assert all(t.subject_id == "cust-001" for t in report.tombstones)
    # Fingerprints prove which records were erased without holding PII.
    assert len({t.record_fingerprint for t in report.tombstones}) == 3
    assert all("example.com" not in t.record_fingerprint for t in report.tombstones)
    assert store.verify_erasure("cust-001")
    assert not store.verify_erasure("cust-002")  # other subjects untouched
    assert len(store.datasets["customers"]) == 1  # only cust-002 remains
    downstreams = {p.downstream_system for p in report.propagation}
    assert downstreams == {"analytics_warehouse", "crm"}


def test_erasure_of_unknown_subject_is_a_no_op():
    _, service = _service()
    report = service.erase("cust-999")
    assert report.datasets_erased == {}
    assert report.tombstones == []
    assert report.propagation == []
