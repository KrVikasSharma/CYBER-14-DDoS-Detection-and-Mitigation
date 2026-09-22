from asyncio import TimeoutError, wait_for

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from app.auth.config import get_auth_settings
from app.auth.models import UserRole
from app.auth.tokens import InvalidTokenError, decode_access_token
from app.services.streaming_service import StreamingService, get_streaming_service

router = APIRouter()


async def require_websocket_access(websocket: WebSocket) -> None:
    auth_settings = get_auth_settings()
    if not auth_settings.auth_enabled:
        return None

    token = websocket.query_params.get("access_token")
    if not token:
        authorization = websocket.headers.get("authorization")
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()

    if not token:
        await websocket.close(code=1008, reason="unauthorized")
        raise WebSocketDisconnect()

    try:
        user = decode_access_token(
            token,
            auth_settings.auth_secret_key or "",
            auth_settings.auth_access_token_expire_minutes * 60,
        )
    except InvalidTokenError:
        await websocket.close(code=1008, reason="unauthorized")
        raise WebSocketDisconnect()

    if user.role not in {UserRole.OPERATOR, UserRole.ADMIN}:
        await websocket.close(code=1008, reason="forbidden")
        raise WebSocketDisconnect()

    return None


@router.websocket("/ws/traffic")
async def traffic_stream(
    websocket: WebSocket,
    _auth: None = Depends(require_websocket_access),
    streaming_service: StreamingService = Depends(get_streaming_service),
) -> None:
    await websocket.accept()
    connection_id = streaming_service.connect()
    try:
        while True:
            try:
                message = await wait_for(
                    websocket.receive(),
                    timeout=streaming_service._settings.websocket_idle_timeout_seconds,
                )
            except TimeoutError:
                await websocket.send_json(
                    streaming_service._error("idle_timeout", "The streaming connection was idle too long.")
                )
                await websocket.close(code=1000)
                return

            message_type = message.get("type")
            if message_type == "websocket.disconnect":
                return
            if message_type == "websocket.receive":
                payload = message.get("text")
                if payload is None:
                    payload = message.get("bytes")
                result = streaming_service.process_message(connection_id, payload or "")
                await websocket.send_json(result)
                if result.get("error_code") in {"message_too_large", "rate_limit_exceeded"}:
                    await websocket.close(code=1008)
                    return
    except WebSocketDisconnect:
        return
    finally:
        streaming_service.disconnect(connection_id)
