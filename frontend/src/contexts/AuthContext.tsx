import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

export interface User {
  email: string
  name:  string
  role:  string
}

interface AuthCtx {
  user:    User | null
  token:   string | null
  loading: boolean
  login:   (token: string, user: User) => void
  logout:  () => void
}

const AuthContext = createContext<AuthCtx>({
  user: null, token: null, loading: true,
  login: () => {}, logout: () => {},
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user,    setUser]    = useState<User | null>(null)
  const [token,   setToken]   = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const storedToken = localStorage.getItem('cti_token')
    if (!storedToken) { setLoading(false); return }

    fetch(`${API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${storedToken}` },
    })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then((u: User) => { setToken(storedToken); setUser(u) })
      .catch(() => { localStorage.removeItem('cti_token') })
      .finally(() => setLoading(false))
  }, [])

  const login = (t: string, u: User) => {
    localStorage.setItem('cti_token', t)
    setToken(t)
    setUser(u)
  }

  const logout = () => {
    localStorage.removeItem('cti_token')
    setToken(null)
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
