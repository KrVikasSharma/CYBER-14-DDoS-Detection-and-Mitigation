from datetime import datetime, timezone
import pytest

from app.core.time import format_iso_utc, format_ist, now_utc, parse_iso_to_utc, to_ist
from app.db.database import get_session_factory
from app.db.repository import get_detections_history, persist_detection_event


def test_now_utc_is_timezone_aware_utc():
    now = now_utc()
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc


def test_format_iso_utc_always_has_z():
    now = datetime(2026, 9, 22, 2, 51, 45, tzinfo=timezone.utc)
    formatted = format_iso_utc(now)
    assert formatted == "2026-09-22T02:51:45Z"

    # Naive datetime is also treated as UTC
    naive = datetime(2026, 9, 22, 2, 51, 45)
    formatted_naive = format_iso_utc(naive)
    assert formatted_naive == "2026-09-22T02:51:45Z"

    assert format_iso_utc(None) is None


def test_parse_iso_to_utc_formats():
    # ISO with Z
    dt1 = parse_iso_to_utc("2026-09-22T02:51:45Z")
    assert dt1 == datetime(2026, 9, 22, 2, 51, 45, tzinfo=timezone.utc)

    # ISO without Z (treated as UTC)
    dt2 = parse_iso_to_utc("2026-09-22T02:51:45")
    assert dt2 == datetime(2026, 9, 22, 2, 51, 45, tzinfo=timezone.utc)

    # SQL format with space
    dt3 = parse_iso_to_utc("2026-09-22 02:51:45")
    assert dt3 == datetime(2026, 9, 22, 2, 51, 45, tzinfo=timezone.utc)

    # Invalid input
    assert parse_iso_to_utc("not-a-date") is None
    assert parse_iso_to_utc(None) is None


def test_to_ist_conversion():
    utc_time = datetime(2026, 9, 22, 2, 51, 45, tzinfo=timezone.utc)
    ist_time = to_ist(utc_time)
    assert ist_time is not None
    assert ist_time.hour == 8
    assert ist_time.minute == 21
    assert ist_time.second == 45
    assert format_ist(utc_time) == "22 Sep 2026, 08:21:45 AM IST"


def test_repository_persists_flow_timestamp_and_formats_utc_z():
    session_factory = get_session_factory()
    with session_factory() as session:
        flow_event_time = "2026-09-22T02:51:45Z"
        payload = {
            "traffic_rate": 1500.0,
            "metadata": {
                "source_ip": "198.51.100.99",
                "source_port": 50001,
                "destination_ip": "10.0.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "timestamp": flow_event_time,
            },
            "o2": {
                "label": 1,
                "confidence": 0.99,
                "threshold": 0.50,
            },
            "o3": {
                "attack_type": "SYN",
                "confidence": 0.98,
                "threshold": 0.80,
            },
            "mitigation": {
                "decision": "BLOCK",
                "reason": "Test SYN attack",
                "duration_seconds": 300,
            },
            "latency": {
                "total_analysis_ms": 12.34,
            },
            "timestamp": "2026-09-22T02:51:45.012345Z",
        }
        res = persist_detection_event(session, payload, actor="test_tz")
        assert res["traffic_event_id"] is not None
        assert res["detection_id"] is not None

        # Verify through get_detections_history that created_at has 'Z'
        history = get_detections_history(session, page=1, page_size=5)
        assert len(history["items"]) > 0
        latest = history["items"][0]
        assert latest["created_at"].endswith("Z")
        assert latest["latency_ms"] is not None
