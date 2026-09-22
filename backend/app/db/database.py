from collections.abc import Generator
from datetime import datetime, timezone
import logging
from time import perf_counter
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.time import format_iso_utc, now_utc
from app.db.models import AttackIncident, AuditLog, Base, Detection, MitigationAction, TrafficEvent

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None
_last_successful_connection: datetime | None = None


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        settings = get_settings()
        db_url = getattr(settings, "database_url", "mysql+pymysql://root:root@127.0.0.1:3306/cyber14_ddos")
        
        # Determine engine options based on driver
        engine_kwargs: dict[str, Any] = {
            "pool_pre_ping": True,
            "pool_recycle": getattr(settings, "db_pool_recycle", 3600),
        }
        if not db_url.startswith("sqlite"):
            engine_kwargs["pool_size"] = getattr(settings, "db_pool_size", 10)
            engine_kwargs["max_overflow"] = getattr(settings, "db_max_overflow", 20)
            engine_kwargs["connect_args"] = {"init_command": "SET time_zone = '+00:00'"}

        _engine = create_engine(db_url, **engine_kwargs)
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    session_factory = get_session_factory()
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def sanitize_db_url(url_str: str) -> dict[str, Any]:
    """Parse database URL and extract safe public metadata without credentials."""
    try:
        parsed = urlparse(url_str.replace("mysql+pymysql://", "http://").replace("sqlite:///", "sqlite:///"))
        db_name = parsed.path.lstrip("/") if parsed.path else "cyber14_ddos"
        return {
            "host": parsed.hostname or "127.0.0.1",
            "port": parsed.port or 3306,
            "database_name": db_name,
        }
    except Exception:
        return {
            "host": "127.0.0.1",
            "port": 3306,
            "database_name": "cyber14_ddos",
        }


def check_database_health() -> dict[str, Any]:
    """Check database health, measure round-trip latency, and count table records."""
    global _last_successful_connection
    settings = get_settings()
    db_url = getattr(settings, "database_url", "mysql+pymysql://root:root@127.0.0.1:3306/cyber14_ddos")
    meta = sanitize_db_url(db_url)

    started = perf_counter()
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            latency_ms = round((perf_counter() - started) * 1000, 2)
            _last_successful_connection = now_utc()

        # Count records across all 5 tables
        tables_count: dict[str, int] = {}
        session_factory = get_session_factory()
        with session_factory() as session:
            try:
                tables_count["traffic_events"] = session.scalar(select(func.count(TrafficEvent.id))) or 0
                tables_count["detections"] = session.scalar(select(func.count(Detection.id))) or 0
                tables_count["attack_incidents"] = session.scalar(select(func.count(AttackIncident.id))) or 0
                tables_count["mitigation_actions"] = session.scalar(select(func.count(MitigationAction.id))) or 0
                tables_count["audit_logs"] = session.scalar(select(func.count(AuditLog.id))) or 0
            except Exception as e:
                logger.debug(f"Could not count tables (schema may need init): {e}")

        return {
            "status": "connected",
            "database_name": meta["database_name"],
            "host": meta["host"],
            "port": meta["port"],
            "latency_ms": latency_ms,
            "last_successful_connection": format_iso_utc(_last_successful_connection),
            "tables": tables_count,
        }
    except Exception as exc:
        latency_ms = round((perf_counter() - started) * 1000, 2)
        safe_msg = str(exc)
        # Strip potential password strings if leaked in exception
        if "@" in safe_msg and "://" in safe_msg:
            safe_msg = safe_msg.split("@")[-1]
        return {
            "status": "disconnected",
            "database_name": meta["database_name"],
            "host": meta["host"],
            "port": meta["port"],
            "latency_ms": None,
            "last_successful_connection": format_iso_utc(_last_successful_connection),
            "error": safe_msg[:200],
            "tables": {},
        }
