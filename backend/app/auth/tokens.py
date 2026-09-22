from datetime import datetime, timezone

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.auth.models import LocalUser, UserRole


class InvalidTokenError(ValueError):
    pass


def create_access_token(user: LocalUser, secret: str, expires_in_seconds: int) -> str:
    serializer = URLSafeTimedSerializer(secret, salt="cyber14-local-access")
    return serializer.dumps({"sub": user.username, "role": user.role.value, "auth_mode": user.auth_mode})


def decode_access_token(token: str, secret: str, max_age: int) -> LocalUser:
    serializer = URLSafeTimedSerializer(secret, salt="cyber14-local-access")
    try:
        payload = serializer.loads(token, max_age=max_age)
        return LocalUser(
            username=str(payload["sub"]),
            role=UserRole(str(payload["role"])),
            auth_mode="local_demo",
        )
    except (BadSignature, SignatureExpired, KeyError, ValueError, TypeError) as exc:
        raise InvalidTokenError("Invalid or expired access token") from exc
