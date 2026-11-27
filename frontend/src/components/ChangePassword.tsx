import { useState } from 'react'
import { createPortal } from 'react-dom'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

/** Botón + diálogo para que cualquier usuario cambie su contraseña. Al cambiarla se cierran todas sus sesiones. */
export default function ChangePasswordButton({ className = '' }: { className?: string }) {
  const { token, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)

  const close = () => { setOpen(false); setCurrent(''); setNext(''); setConfirm(''); setError('') }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (next !== confirm) { setError('La confirmación no coincide'); return }
    setBusy(true); setError('')
    try {
      const r = await fetch(`${API}/auth/change-password`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ current, new: next }),
      })
      const data = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(data.detail ?? 'No se pudo cambiar la contraseña')
      setDone(true)
      setTimeout(logout, 2500)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo cambiar la contraseña')
    } finally { setBusy(false) }
  }

  const input = 'w-full rounded-lg px-3 py-2 text-xs text-slate-200 outline-none'
  const inputStyle = { background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }

  return (
    <>
      <button onClick={() => setOpen(true)} className={`text-[10px] py-1.5 rounded-lg text-slate-500 hover:text-slate-300 ${className}`}
              style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
        🔑 Cambiar contraseña
      </button>
      {open && createPortal(
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={close}>
          <form onSubmit={submit} onClick={e => e.stopPropagation()} className="w-full max-w-sm rounded-xl p-5 space-y-3"
                style={{ background: '#151a0f', border: '1px solid rgba(212,189,85,0.3)' }}>
            <p className="text-sm font-bold text-slate-100">🔑 Cambiar contraseña</p>
            {done ? (
              <p className="text-xs text-green-400">Contraseña actualizada. Se cerrarán tus sesiones; vuelve a entrar con la nueva clave.</p>
            ) : (
              <>
                <input type="password" autoComplete="current-password" placeholder="Contraseña actual" value={current}
                       onChange={e => setCurrent(e.target.value)} className={input} style={inputStyle} required />
                <input type="password" autoComplete="new-password" placeholder="Nueva (10+ caracteres, letras y números)" value={next}
                       onChange={e => setNext(e.target.value)} className={input} style={inputStyle} required minLength={10} />
                <input type="password" autoComplete="new-password" placeholder="Confirmar nueva contraseña" value={confirm}
                       onChange={e => setConfirm(e.target.value)} className={input} style={inputStyle} required />
                {error && <p className="text-[11px] text-red-400">{error}</p>}
                <div className="flex gap-2 justify-end pt-1">
                  <button type="button" onClick={close} className="px-3 py-1.5 rounded-lg text-xs text-slate-400"
                          style={{ border: '1px solid rgba(255,255,255,0.1)' }}>Cancelar</button>
                  <button type="submit" disabled={busy} className="px-3 py-1.5 rounded-lg text-xs font-semibold disabled:opacity-40"
                          style={{ background: 'rgba(212,189,85,0.15)', border: '1px solid rgba(212,189,85,0.45)', color: '#e0cf74' }}>
                    {busy ? 'Guardando…' : 'Guardar'}
                  </button>
                </div>
              </>
            )}
          </form>
        </div>,
        document.body,
      )}
    </>
  )
}
