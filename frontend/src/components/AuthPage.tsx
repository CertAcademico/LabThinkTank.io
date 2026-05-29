import { useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const DOMAIN  = 'universidadean.edu.co'

type Mode = 'login' | 'register'

function Field({
  label, type = 'text', value, onChange, placeholder, hint,
}: {
  label: string; type?: string; value: string;
  onChange: (v: string) => void; placeholder?: string; hint?: string
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-slate-400">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        required
        className="w-full rounded-lg px-3 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition-all focus:ring-1"
        style={{
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.08)',
        }}
        onFocus={e => (e.currentTarget.style.borderColor = 'rgba(34,211,238,0.5)')}
        onBlur={e  => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
      />
      {hint && <p className="text-[10px] text-slate-600">{hint}</p>}
    </div>
  )
}

export default function AuthPage() {
  const { login } = useAuth()
  const [mode,     setMode]     = useState<Mode>('login')
  const [name,     setName]     = useState('')
  const [email,    setEmail]    = useState('')
  const [password, setPassword] = useState('')
  const [confirm,  setConfirm]  = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)
  const [success,  setSuccess]  = useState('')

  const isEanEmail = email.trim().toLowerCase().endsWith(`@${DOMAIN}`)

  const submit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (mode === 'register' && password !== confirm) {
      setError('Las contraseñas no coinciden')
      return
    }

    setLoading(true)
    try {
      if (mode === 'register') {
        const r = await fetch(`${API_URL}/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, password }),
        })
        const data = await r.json()
        if (!r.ok) throw new Error(data.detail ?? 'Error al registrarse')
        setSuccess(`Cuenta creada para ${data.name}. Ahora inicia sesión.`)
        setMode('login')
        setName(''); setPassword(''); setConfirm('')
      } else {
        const r = await fetch(`${API_URL}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        })
        const data = await r.json()
        if (!r.ok) throw new Error(data.detail ?? 'Error al iniciar sesión')

        const meRes = await fetch(`${API_URL}/auth/me`, {
          headers: { Authorization: `Bearer ${data.token}` },
        })
        const user = await meRes.json()
        login(data.token, user)
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Error desconocido')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex" style={{ background: '#030712' }}>

      {/* ── Left: branding ───────────────────────────────────────────────── */}
      <div className="hidden lg:flex flex-col justify-between w-[480px] shrink-0 p-12 border-r"
           style={{ background: 'rgba(8,12,25,0.97)', borderColor: 'rgba(255,255,255,0.05)' }}>
        <div>
          {/* Logo */}
          <div className="flex items-center gap-3 mb-16">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                 style={{ background: 'rgba(34,211,238,0.12)', boxShadow: '0 0 24px rgba(34,211,238,0.2)' }}>
              <svg viewBox="0 0 24 24" className="w-5 h-5 text-cyan-400" fill="none"
                   stroke="currentColor" strokeWidth="2">
                <polygon points="12 2 2 7 12 12 22 7 12 2" />
                <polyline points="2 17 12 22 22 17" />
                <polyline points="2 12 12 17 22 12" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-bold text-white leading-none">CTI Nexus</p>
              <p className="text-[9px] font-mono text-slate-600 tracking-widest">SANDBOX LAB</p>
            </div>
          </div>

          <h1 className="text-3xl font-bold text-white leading-tight mb-4">
            Aprende ciencia de datos<br />
            <span style={{ color: '#22d3ee' }}>con datos reales de CTI</span>
          </h1>
          <p className="text-slate-500 text-sm leading-relaxed mb-10">
            Plataforma de aprendizaje interactivo para estudiantes de la Universidad Ean.
            Practica Python, ETL, Machine Learning y visualización de datos usando
            inteligencia de amenazas cibernéticas real.
          </p>

          {/* Feature list */}
          {[
            { icon: '🐍', label: 'Python interactivo en el browser — sin instalar nada' },
            { icon: '🔧', label: 'ETL, limpieza y parseo de datos de SIEM' },
            { icon: '📊', label: 'Visualizaciones con Matplotlib' },
            { icon: '🤖', label: 'ML y clustering con scikit-learn' },
            { icon: '🛡️', label: 'Datasets reales de Cyber Threat Intelligence' },
          ].map(f => (
            <div key={f.label} className="flex items-start gap-3 mb-4">
              <span className="text-lg shrink-0">{f.icon}</span>
              <span className="text-xs text-slate-400 leading-relaxed">{f.label}</span>
            </div>
          ))}
        </div>

        <p className="text-[10px] text-slate-700 font-mono">
          Universidad Ean · Programa de Ciberseguridad · {new Date().getFullYear()}
        </p>
      </div>

      {/* ── Right: form ──────────────────────────────────────────────────── */}
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md">

          {/* Card */}
          <div className="rounded-2xl p-8"
               style={{
                 background: 'rgba(15,23,42,0.7)',
                 backdropFilter: 'blur(20px)',
                 border: '1px solid rgba(255,255,255,0.07)',
               }}>

            {/* Tab toggle */}
            <div className="flex rounded-xl p-1 mb-8"
                 style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
              {(['login', 'register'] as Mode[]).map(m => (
                <button key={m} onClick={() => { setMode(m); setError(''); setSuccess('') }}
                        className="flex-1 py-2 rounded-lg text-sm font-medium transition-all"
                        style={mode === m ? {
                          background: 'rgba(34,211,238,0.1)',
                          color: '#22d3ee',
                          border: '1px solid rgba(34,211,238,0.25)',
                        } : { color: '#475569' }}>
                  {m === 'login' ? 'Iniciar sesión' : 'Registrarse'}
                </button>
              ))}
            </div>

            <form onSubmit={submit} className="space-y-4">
              {mode === 'register' && (
                <Field label="Nombre completo" value={name} onChange={setName}
                       placeholder="Ana García López" />
              )}

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-400">Email institucional</label>
                <div className="relative">
                  <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder={`estudiante@${DOMAIN}`}
                    required
                    className="w-full rounded-lg px-3 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none pr-8 transition-all"
                    style={{
                      background: 'rgba(255,255,255,0.04)',
                      border: `1px solid ${isEanEmail && email ? 'rgba(74,222,128,0.4)' : 'rgba(255,255,255,0.08)'}`,
                    }}
                    onFocus={e => (e.currentTarget.style.borderColor = 'rgba(34,211,238,0.5)')}
                    onBlur={e  => (e.currentTarget.style.borderColor =
                      isEanEmail && email ? 'rgba(74,222,128,0.4)' : 'rgba(255,255,255,0.08)')}
                  />
                  {isEanEmail && email && (
                    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-green-400 text-xs">✓</span>
                  )}
                </div>
                <p className="text-[10px] text-slate-600">Solo se permiten cuentas @{DOMAIN}</p>
              </div>

              <Field label="Contraseña" type="password" value={password} onChange={setPassword}
                     placeholder="Mínimo 8 caracteres"
                     hint={mode === 'register' ? 'Mínimo 8 caracteres' : undefined} />

              {mode === 'register' && (
                <Field label="Confirmar contraseña" type="password" value={confirm} onChange={setConfirm}
                       placeholder="Repite tu contraseña" />
              )}

              {error && (
                <div className="rounded-lg px-3 py-2.5 text-xs text-red-300"
                     style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                  {error}
                </div>
              )}
              {success && (
                <div className="rounded-lg px-3 py-2.5 text-xs text-green-300"
                     style={{ background: 'rgba(74,222,128,0.08)', border: '1px solid rgba(74,222,128,0.2)' }}>
                  {success}
                </div>
              )}

              <button type="submit" disabled={loading}
                      className="w-full py-2.5 rounded-lg text-sm font-semibold transition-all disabled:opacity-50 mt-2"
                      style={{
                        background: 'linear-gradient(135deg, rgba(34,211,238,0.2), rgba(167,139,250,0.2))',
                        border: '1px solid rgba(34,211,238,0.3)',
                        color: '#22d3ee',
                      }}>
                {loading ? 'Procesando...' : mode === 'login' ? 'Entrar al Lab →' : 'Crear cuenta →'}
              </button>
            </form>

            <p className="text-center text-[10px] text-slate-700 mt-6">
              CTI Nexus Sandbox Lab · Solo uso educativo
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
