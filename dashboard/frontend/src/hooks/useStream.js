import { useCallback, useEffect, useRef, useState } from 'react'
import { websocketUrl } from '../services/api'

export function useStream(onEvent, enabled = false, options = {}) {
  const {
    autoReconnect = true,
    heartbeatIntervalMs = 15000,
  } = options

  const socketRef = useRef(null)
  const retryRef = useRef(null)
  const heartbeatRef = useRef(null)
  const attemptsRef = useRef(0)
  const enabledRef = useRef(enabled)
  const autoReconnectRef = useRef(autoReconnect)
  const [state, setState] = useState('DISCONNECTED')

  useEffect(() => {
    autoReconnectRef.current = autoReconnect
  }, [autoReconnect])

  const clearRetry = useCallback(() => {
    if (retryRef.current) {
      window.clearTimeout(retryRef.current)
      retryRef.current = null
    }
  }, [])

  const clearHeartbeat = useCallback(() => {
    if (heartbeatRef.current) {
      window.clearInterval(heartbeatRef.current)
      heartbeatRef.current = null
    }
  }, [])

  const stop = useCallback(() => {
    enabledRef.current = false
    clearRetry()
    clearHeartbeat()
    attemptsRef.current = 0
    if (socketRef.current) {
      socketRef.current.onopen = null
      socketRef.current.onmessage = null
      socketRef.current.onerror = null
      socketRef.current.onclose = null
      if (
        socketRef.current.readyState === WebSocket.OPEN ||
        socketRef.current.readyState === WebSocket.CONNECTING
      ) {
        socketRef.current.close(1000, 'client_stopped')
      }
      socketRef.current = null
    }
    setState('DISCONNECTED')
  }, [clearRetry, clearHeartbeat])

  const start = useCallback(() => {
    enabledRef.current = true
    const token = localStorage.getItem('cyber14_access_token')
    if (!token) {
      setState('DISCONNECTED')
      return
    }
    if (
      socketRef.current &&
      (socketRef.current.readyState === WebSocket.OPEN || socketRef.current.readyState === WebSocket.CONNECTING)
    ) {
      return
    }

    clearRetry()
    clearHeartbeat()
    setState('CONNECTING')
    const socket = new WebSocket(websocketUrl(token))
    socketRef.current = socket

    socket.onopen = () => {
      attemptsRef.current = 0
      setState('CONNECTED')

      clearHeartbeat()
      if (heartbeatIntervalMs > 0) {
        heartbeatRef.current = window.setInterval(() => {
          if (socketRef.current?.readyState === WebSocket.OPEN) {
            try {
              socketRef.current.send(JSON.stringify({ type: 'ping' }))
            } catch {
              // ignore send failures; onclose will handle state
            }
          }
        }, heartbeatIntervalMs)
      }
    }

    socket.onmessage = (message) => {
      try {
        const payload = JSON.parse(message.data)
        // Keepalive heartbeat pong - absorb without passing to event list
        if (payload?.type === 'pong' || payload?.type === 'heartbeat') {
          return
        }
        onEvent(payload)
      } catch {
        onEvent({
          type: 'error',
          error_code: 'invalid_client_message',
          message: 'Stream response was not valid JSON.',
        })
      }
    }

    socket.onerror = () => {
      setState('ERROR')
    }

    socket.onclose = (event) => {
      clearHeartbeat()
      socketRef.current = null

      if (!enabledRef.current) {
        setState('DISCONNECTED')
        return
      }

      if (event.code === 1008) {
        setState('DISCONNECTED')
        return
      }

      if (!autoReconnectRef.current) {
        setState('DISCONNECTED')
        return
      }

      const nextAttempt = attemptsRef.current + 1
      if (nextAttempt <= 5) {
        attemptsRef.current = nextAttempt
        setState('RECONNECTING')
        retryRef.current = window.setTimeout(() => {
          if (enabledRef.current) {
            start()
          }
        }, Math.min(500 * 2 ** (nextAttempt - 1), 8000))
      } else {
        attemptsRef.current = 0
        setState('DISCONNECTED')
      }
    }
  }, [clearRetry, clearHeartbeat, heartbeatIntervalMs, onEvent])

  useEffect(() => {
    enabledRef.current = enabled
    if (!enabled) {
      stop()
      return undefined
    }
    start()
    return () => {
      enabledRef.current = false
      stop()
    }
  }, [enabled, start, stop])

  const send = useCallback((payload) => {
    if (socketRef.current?.readyState !== WebSocket.OPEN) return false
    socketRef.current.send(JSON.stringify(payload))
    return true
  }, [])

  return { state, start, stop, send }
}
