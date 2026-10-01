import { describe, it, expect, vi, beforeEach } from 'vitest'
import { auth } from './auth'
import { api } from './api'

describe('Frontend Auth Service', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('stores token in localStorage upon successful login', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      access_token: 'valid.test.token',
      user: { username: 'admin', role: 'admin' },
    })

    const user = await auth.login('admin', 'password')
    expect(user.username).toBe('admin')
    expect(localStorage.getItem('cyber14_access_token')).toBe('valid.test.token')
  })

  it('restores user from api.me when token exists', async () => {
    localStorage.setItem('cyber14_access_token', 'existing.token')
    vi.spyOn(api, 'me').mockResolvedValue({ username: 'admin', role: 'admin' })

    const user = await auth.me()
    expect(user).toEqual({ username: 'admin', role: 'admin' })
    expect(localStorage.getItem('cyber14_access_token')).toBe('existing.token')
  })

  it('returns null and removes token only when server returns 401 Unauthorized', async () => {
    localStorage.setItem('cyber14_access_token', 'expired.token')
    const err = new Error('Unauthorized')
    err.status = 401
    vi.spyOn(api, 'me').mockRejectedValue(err)

    const user = await auth.me()
    expect(user).toBeNull()
    expect(localStorage.getItem('cyber14_access_token')).toBeNull()
  })

  it('preserves token when transient network/cold-start error occurs (not 401)', async () => {
    localStorage.setItem('cyber14_access_token', 'valid.cold.token')
    const err = new Error('Failed to fetch')
    err.status = 502
    vi.spyOn(api, 'me').mockRejectedValue(err)

    const user = await auth.me()
    expect(user).toBeNull()
    // Token is preserved so next attempt or refresh can succeed
    expect(localStorage.getItem('cyber14_access_token')).toBe('valid.cold.token')
  })

  it('clears localStorage upon explicit logout', async () => {
    localStorage.setItem('cyber14_access_token', 'active.token')
    vi.spyOn(api, 'logout').mockResolvedValue({ logged_out: true })

    await auth.logout()
    expect(localStorage.getItem('cyber14_access_token')).toBeNull()
  })
})
