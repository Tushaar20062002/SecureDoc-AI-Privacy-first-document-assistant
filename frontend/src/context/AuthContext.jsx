import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { authApi, setCsrfToken } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const apply = useCallback((u) => {
    setCsrfToken(u?.csrf_token)
    setUser(u)
    return u
  }, [])

  const refresh = useCallback(async () => {
    try {
      return apply(await authApi.me())
    } catch {
      return apply(null)
    }
  }, [apply])

  useEffect(() => {
    refresh().finally(() => setLoading(false))
  }, [refresh])

  const value = {
    user,
    loading,
    refresh,
    login: async (email, password) => apply(await authApi.login(email, password)),
    register: async (email, password) => apply(await authApi.register(email, password)),
    logout: async () => {
      try {
        await authApi.logout()
      } finally {
        apply(null)
      }
    },
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  return useContext(AuthContext)
}
