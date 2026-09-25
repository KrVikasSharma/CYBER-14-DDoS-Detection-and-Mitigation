import logging
import secrets
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4

from app.auth.config import AuthSettings
from app.auth.models import LocalUser, SecurityEvent, TokenResponse, UserRole
from app.auth.password import hash_password, verify_password
from app.auth.tokens import create_access_token
from app.core.time import now_utc

logger = logging.getLogger(__name__)


class AuthenticationError(ValueError):
    pass


class LoginRateLimitError(AuthenticationError):
    pass


class ConcurrentSessionError(AuthenticationError):
    pass


class AuthService:
    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._active_sessions: dict[str, dict[str, Any]] = {}
        self._events: list[SecurityEvent] = []
        self._lock = RLock()
        self._bootstrap_hash = hash_password(settings.auth_bootstrap_password) if settings.auth_enabled and settings.auth_bootstrap_password else None

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def login(self, username: str, password: str, client_ip: str | None = None) -> TokenResponse:
        correlation_id = str(uuid4())
        resolved_ip = client_ip or "127.0.0.1"
        if not self.settings.auth_enabled:
            user = LocalUser(username="development", role=UserRole.ADMIN, auth_mode="local_development")
            self._record("login_success", user.username, user.role, True, "Authentication disabled for local development", correlation_id, client_ip=resolved_ip)
            return TokenResponse(access_token=None, expires_in_seconds=None, auth_enabled=False, user=user)

        self._check_rate_limit(username)
        valid = secrets.compare_digest(username, self.settings.auth_bootstrap_username) and bool(
            self._bootstrap_hash and verify_password(password, self._bootstrap_hash)
        )
        if not valid:
            self._record("login_failure", None, None, False, "Invalid credentials", correlation_id, client_ip=resolved_ip)
            raise AuthenticationError("Invalid username or password")

        now = now_utc().timestamp()
        with self._lock:
            active = self._active_sessions.get(username)
            if active:
                if active.get("expires_at", 0) > now:
                    self._record(
                        "login_rejected_concurrent",
                        username,
                        UserRole(self.settings.auth_bootstrap_role),
                        False,
                        "User already has an active session. Please logout from the existing session first.",
                        correlation_id,
                        client_ip=resolved_ip,
                    )
                    raise ConcurrentSessionError("User already has an active session. Please logout from the existing session first.")
                else:
                    self._active_sessions.pop(username, None)

            expires_in_sec = self.settings.auth_access_token_expire_minutes * 60
            self._active_sessions[username] = {
                "session_id": correlation_id,
                "created_at": now,
                "expires_at": now + expires_in_sec,
                "client_ip": resolved_ip,
                "username": username,
            }

        user = LocalUser(username=username, role=UserRole(self.settings.auth_bootstrap_role), auth_mode="local_demo")
        token = create_access_token(user, self.settings.auth_secret_key or "", self.settings.auth_access_token_expire_minutes * 60)
        self._record("login_success", username, user.role, True, "Authenticated", correlation_id, client_ip=resolved_ip)
        return TokenResponse(
            access_token=token,
            expires_in_seconds=self.settings.auth_access_token_expire_minutes * 60,
            auth_enabled=True,
            user=user,
        )

    def logout(self, user: LocalUser | None, client_ip: str | None = None) -> dict[str, str | bool]:
        resolved_ip = client_ip or "127.0.0.1"
        with self._lock:
            if user and user.username in self._active_sessions:
                self._active_sessions.pop(user.username, None)
        self._record("logout", user.username if user else None, user.role if user else None, True, "Client token cleared; session released", str(uuid4()), client_ip=resolved_ip)
        return {"logged_out": True, "token_revocation": "session_released"}

    def _check_rate_limit(self, username: str) -> None:
        now = now_utc().timestamp()
        attempts = self._attempts[username]
        while attempts and attempts[0] <= now - 60:
            attempts.popleft()
        if len(attempts) >= self.settings.auth_login_max_attempts_per_minute:
            raise LoginRateLimitError("Login temporarily unavailable; retry later")
        attempts.append(now)

    def _record(self, event_type: str, username: str | None, role: UserRole | None, success: bool, reason: str, correlation_id: str, client_ip: str | None = None) -> None:
        event = SecurityEvent(event_type=event_type, username=username, role=role, success=success, reason=reason, correlation_id=correlation_id, client_ip=client_ip)
        with self._lock:
            self._events.append(event)
        logger.info("auth_event type=%s username=%s role=%s client_ip=%s success=%s correlation_id=%s", event_type, username or "anonymous", role.value if role else "none", client_ip or "unknown", success, correlation_id)
        try:
            from app.db.database import get_session_factory
            from app.db.repository import log_audit_event
            session_factory = get_session_factory()
            with session_factory() as db_session:
                log_audit_event(
                    db=db_session,
                    event_type="LOGIN" if "login" in event_type else ("LOGOUT" if event_type == "logout" else event_type.upper()),
                    actor=username or "anonymous",
                    action=event_type.upper(),
                    resource_type="auth_session",
                    resource_id=correlation_id,
                    details={"success": success, "reason": reason, "role": role.value if role else None, "client_ip": client_ip or "127.0.0.1"},
                )
        except Exception as exc:
            logger.debug("Database audit log skipped for auth event: %s", exc)
