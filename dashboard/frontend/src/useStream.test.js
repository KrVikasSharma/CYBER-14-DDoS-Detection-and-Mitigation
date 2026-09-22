import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useStream } from './hooks/useStream'

class MockWebSocket {
  static instances = []
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  constructor(url) {
    this.url = url
    this.readyState = 0
    this.onopen = null
    this.onmessage = null
    this.onerror = null
    this.onclose = null
    MockWebSocket.instances.push(this)
  }

  send(data) {
    this.lastSent = data
  }

  close() {
    this.readyState = 3
    this.onclose?.({ code: 1000, reason: 'closed' })
  }
}

describe('useStream websocket lifecycle', () => {
  beforeEach(() => {
    vi.stubGlobal('WebSocket', MockWebSocket)
    vi.useFakeTimers()
    localStorage.clear()
    MockWebSocket.instances = []
  })

  afterEach(() => {
    vi.clearAllTimers()
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('creates the expected ws URL and connects after login token is present', () => {
    localStorage.setItem('cyber14_access_token', 'abc123')
    const onEvent = vi.fn()
    const { result } = renderHook(() => useStream(onEvent, true))
    expect(MockWebSocket.instances).toHaveLength(1)
    expect(MockWebSocket.instances[0].url).toContain('ws://localhost:8000/ws/traffic')
    expect(MockWebSocket.instances[0].url).toContain('access_token=abc123')
    expect(result.current.state).toBe('CONNECTING')
    act(() => {
      MockWebSocket.instances[0].readyState = 1
      MockWebSocket.instances[0].onopen?.()
    })
    expect(result.current.state).toBe('CONNECTED')
  })

  it('moves to disconnect when the socket closes and stops reconnecting after cleanup', () => {
    const onEvent = vi.fn()
    localStorage.setItem('cyber14_access_token', 'abc123')
    const { result, unmount } = renderHook(() => useStream(onEvent, true))
    act(() => {
      MockWebSocket.instances[0].readyState = 1
      MockWebSocket.instances[0].onopen?.()
    })
    act(() => {
      MockWebSocket.instances[0].onclose?.({ code: 1006, reason: 'network lost' })
    })
    expect(result.current.state).toBe('RECONNECTING')
    act(() => {
      result.current.stop()
    })
    expect(result.current.state).toBe('DISCONNECTED')
    unmount()
  })

  it('periodically sends keepalive heartbeat ping and ignores pong messages', () => {
    const onEvent = vi.fn()
    localStorage.setItem('cyber14_access_token', 'abc123')
    const { result } = renderHook(() => useStream(onEvent, true, { heartbeatIntervalMs: 1000 }))
    act(() => {
      MockWebSocket.instances[0].readyState = 1
      MockWebSocket.instances[0].onopen?.()
    })
    expect(result.current.state).toBe('CONNECTED')

    // Advance timer by 1000ms to trigger heartbeat
    act(() => {
      vi.advanceTimersByTime(1000)
    })
    expect(MockWebSocket.instances[0].lastSent).toBe(JSON.stringify({ type: 'ping' }))

    // Simulate receiving pong message
    act(() => {
      MockWebSocket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'pong', timestamp: 12345 }) })
    })
    // onEvent must not be called for pong
    expect(onEvent).not.toHaveBeenCalled()

    // Simulate regular detection result
    act(() => {
      MockWebSocket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'detection_result', test: true }) })
    })
    expect(onEvent).toHaveBeenCalledWith({ type: 'detection_result', test: true })
  })

  it('remains disconnected without reconnecting when autoReconnect is false', () => {
    const onEvent = vi.fn()
    localStorage.setItem('cyber14_access_token', 'abc123')
    const { result } = renderHook(() => useStream(onEvent, true, { autoReconnect: false }))
    act(() => {
      MockWebSocket.instances[0].readyState = 1
      MockWebSocket.instances[0].onopen?.()
    })
    expect(result.current.state).toBe('CONNECTED')

    // Server sends idle timeout close
    act(() => {
      MockWebSocket.instances[0].onclose?.({ code: 1000, reason: 'idle_timeout' })
    })
    expect(result.current.state).toBe('DISCONNECTED')

    // Advance time - should not reconnect
    act(() => {
      vi.advanceTimersByTime(10000)
    })
    expect(result.current.state).toBe('DISCONNECTED')
    expect(MockWebSocket.instances).toHaveLength(1)
  })

  it('prevents duplicate socket creation on repeated start calls', () => {
    const onEvent = vi.fn()
    localStorage.setItem('cyber14_access_token', 'abc123')
    const { result } = renderHook(() => useStream(onEvent, true))
    expect(MockWebSocket.instances).toHaveLength(1)
    act(() => {
      result.current.start()
      result.current.start()
    })
    expect(MockWebSocket.instances).toHaveLength(1)
  })
})
