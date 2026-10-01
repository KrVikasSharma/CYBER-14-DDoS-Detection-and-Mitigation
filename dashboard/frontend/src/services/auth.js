import { api } from './api'

const TOKEN_KEY = 'cyber14_access_token'

export const auth = {
  async login(username, password) {
    const session = await api.login({ username, password })
    if (session.access_token) localStorage.setItem(TOKEN_KEY, session.access_token)
    return session.user
  },
  async me() {
    if (!localStorage.getItem(TOKEN_KEY)) return null
    try {
      return await api.me()
    } catch (err) {
      if (err?.status === 401) {
        localStorage.removeItem(TOKEN_KEY)
      }
      return null
    }
  },
  async logout() {
    try {
      await api.logout()
    } finally {
      localStorage.removeItem(TOKEN_KEY)
    }
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY)
  },
}