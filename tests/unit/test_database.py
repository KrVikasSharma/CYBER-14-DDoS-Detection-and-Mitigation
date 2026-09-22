from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy.pool import StaticPool

from app.auth.dependencies import get_current_user
from app.auth.models import LocalUser, UserRole
from app.db.database import check_database_health, get_db
from app.db.models import AttackIncident, AuditLog, Base, Detection, MitigationAction, TrafficEvent
from app.db.repository import (
    generate_incident_id,
    get_audit_logs,
    get_detections_history,
    get_incident_by_id,
    get_incidents,
    get_mitigation_history,
    log_audit_event,
    persist_detection_event,
)
from app.main import create_app


@pytest.fixture
def test_engine():
    """Shared in-memory SQLite engine with StaticPool for multi-threaded testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def test_db_session(test_engine):
    """In-memory SQLite session for isolated unit testing."""
    SessionTesting = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = SessionTesting()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def app_with_db(test_engine):
    """FastAPI application with overridden test database session."""
    app = create_app()
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield app
    app.dependency_overrides.clear()


def test_database_health_check():
    """Verify database healthcheck returns sanitized metadata without credentials."""
    health = check_database_health()
    assert health["status"] in {"connected", "disconnected"}
    assert "database_name" in health
    assert "host" in health
    assert "port" in health
    assert "tables" in health
    assert "password" not in health
    assert "root:root" not in str(health)


def test_incident_id_generation(test_db_session):
    """Verify INC-YYYYMMDD-XXXX sequential generation."""
    fixed_date = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
    id1 = generate_incident_id(test_db_session, fixed_date)
    assert id1 == "INC-20260922-0001"

    # Insert incident with id1
    inc1 = AttackIncident(
        incident_id=id1,
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        attack_type="SYN",
        severity="HIGH",
        status="DETECTED",
        first_seen=fixed_date,
        last_seen=fixed_date,
        occurrence_count=1,
    )
    test_db_session.add(inc1)
    test_db_session.commit()

    id2 = generate_incident_id(test_db_session, fixed_date)
    assert id2 == "INC-20260922-0002"


def test_persist_detection_benign_flow(test_db_session):
    """Verify benign detection creates traffic event, detection, and allow mitigation."""
    payload = {
        "metadata": {
            "source_ip": "192.168.1.50",
            "source_port": 54321,
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "protocol": "TCP",
        },
        "traffic_rate": 10.0,
        "o2": {"label": 0, "confidence": 0.999, "threshold": 0.5},
        "o3": {"attack_type": None, "confidence": None, "threshold": 0.8},
        "mitigation": {
            "decision": "ALLOW",
            "reason": "Legitimate flow below flash crowd threshold",
            "duration_seconds": None,
        },
        "latency": {"total_analysis_ms": 12.5},
    }

    result = persist_detection_event(test_db_session, payload, actor="system")
    assert result["traffic_event_id"] is not None
    assert result["detection_id"] is not None
    assert result["incident_id"] is None
    assert result["mitigation_id"] is not None

    # Verify query
    history = get_detections_history(test_db_session, page=1, page_size=10)
    assert history["total"] == 1
    item = history["items"][0]
    assert item["source_ip"] == "192.168.1.50"
    assert item["o2_label"] == 0


def test_persist_detection_attack_aggregation(test_db_session):
    """Verify repeated attacks from same source and attack type aggregate into same incident."""
    payload = {
        "metadata": {
            "source_ip": "198.51.100.15",
            "source_port": 137,
            "destination_ip": "10.0.0.1",
            "destination_port": 137,
            "protocol": "UDP",
        },
        "traffic_rate": 2000.0,
        "o2": {"label": 1, "confidence": 1.0, "threshold": 0.5},
        "o3": {"attack_type": "NETBIOS", "confidence": 0.969, "threshold": 0.8},
        "mitigation": {
            "decision": "BLOCK",
            "reason": "High-confidence attack",
            "duration_seconds": 300,
        },
        "latency": {"total_analysis_ms": 15.0},
    }

    # First observation -> creates incident
    res1 = persist_detection_event(test_db_session, payload, actor="test_client")
    assert res1["incident_id"] is not None
    inc_id = res1["incident_id"]

    inc_data = get_incident_by_id(test_db_session, inc_id)
    assert inc_data is not None
    assert inc_data["occurrence_count"] == 1
    assert inc_data["severity"] == "CRITICAL"

    # Second observation -> aggregates into same incident
    res2 = persist_detection_event(test_db_session, payload, actor="test_client")
    assert res2["incident_id"] == inc_id

    inc_data2 = get_incident_by_id(test_db_session, inc_id)
    assert inc_data2["occurrence_count"] == 2
    assert len(inc_data2["mitigations"]) == 2
    assert len(inc_data2["detections"]) == 2


def test_api_database_status(app_with_db):
    """Verify GET /api/v1/system/database endpoint."""
    app_with_db.dependency_overrides[get_current_user] = lambda: LocalUser(
        username="test_viewer", role=UserRole.VIEWER, auth_mode="local_demo"
    )
    with TestClient(app_with_db) as client:
        resp = client.get("/api/v1/system/database")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "host" in data
        assert "database_name" in data


def test_api_incidents_pagination_and_detail(app_with_db, test_db_session):
    """Verify GET /api/v1/incidents and GET /api/v1/incidents/{id}."""
    app_with_db.dependency_overrides[get_current_user] = lambda: LocalUser(
        username="test_analyst", role=UserRole.ANALYST, auth_mode="local_demo"
    )

    # Insert test incident
    fixed_time = datetime.now(timezone.utc)
    inc = AttackIncident(
        incident_id="INC-20260922-0042",
        source_ip="192.168.1.102",
        destination_ip="10.0.0.1",
        attack_type="UDP",
        severity="HIGH",
        status="DETECTED",
        first_seen=fixed_time,
        last_seen=fixed_time,
        occurrence_count=5,
    )
    test_db_session.add(inc)
    test_db_session.commit()

    with TestClient(app_with_db) as client:
        # List incidents
        resp = client.get("/api/v1/incidents?page=1&page_size=10&attack_type=UDP")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["incident_id"] == "INC-20260922-0042"

        # Detail
        detail_resp = client.get("/api/v1/incidents/INC-20260922-0042")
        assert detail_resp.status_code == 200
        assert detail_resp.json()["occurrence_count"] == 5

        # Not found
        nf_resp = client.get("/api/v1/incidents/INC-99999999-9999")
        assert nf_resp.status_code == 404


def test_api_audit_logs_rbac(app_with_db):
    """Verify RBAC on audit logs (Analyst/Operator/Admin allowed, Viewer restricted)."""
    with TestClient(app_with_db) as client:
        # Viewer -> 403 Forbidden
        app_with_db.dependency_overrides[get_current_user] = lambda: LocalUser(
            username="viewer_user", role=UserRole.VIEWER, auth_mode="local_demo"
        )
        resp_viewer = client.get("/api/v1/audit/logs")
        assert resp_viewer.status_code == 403

        # Analyst -> 200 OK
        app_with_db.dependency_overrides[get_current_user] = lambda: LocalUser(
            username="analyst_user", role=UserRole.ANALYST, auth_mode="local_demo"
        )
        resp_analyst = client.get("/api/v1/audit/logs")
        assert resp_analyst.status_code == 200


def test_database_failure_does_not_halt_detection():
    """Verify that if database connection fails, DetectionService.analyze continues safely."""
    import json
    from pathlib import Path

    from app.core.config import Settings
    from app.schemas.detection import DetectionAnalyzeRequest
    from app.services.detection_service import DetectionService

    # Provide an invalid DB URL that will trigger connection error
    test_settings = Settings(
        demo_mode=True,
        database_url="mysql+pymysql://invalid_user:invalid_pass@127.0.0.1:9999/nonexistent_db",
    )
    svc = DetectionService(test_settings)

    scenarios_path = Path("data/demo/demo_scenarios.json")
    with open(scenarios_path, encoding="utf-8") as f:
        scenarios = json.load(f)
    benign_features = scenarios["benign"]["features"]

    req = DetectionAnalyzeRequest(
        source_identifier="test_failover",
        traffic_rate=10,
        features=benign_features,
    )

    # analyze() should complete without raising an unhandled exception
    response = svc.analyze(req)
    assert response is not None
    assert response.o2 is not None
    assert response.mitigation is not None


def test_api_live_analytics(app_with_db):
    """Verify GET /api/v1/analytics/live returns real aggregated metrics."""
    app_with_db.dependency_overrides[get_current_user] = lambda: LocalUser(
        username="test_viewer", role=UserRole.VIEWER, auth_mode="local_demo"
    )
    with TestClient(app_with_db) as client:
        resp = client.get("/api/v1/analytics/live")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "current_rate" in data
        assert "active_connections" in data
        assert "unique_sources" in data
        assert "detected_attacks" in data
        assert "blocked" in data
        assert "rate_limited" in data
        assert "allow" in data
        assert "latency" in data
        assert "attack_distribution" in data
        assert "mitigation_distribution" in data


