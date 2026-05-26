import { useRef, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-900 text-red-300 border-red-700',
  high:     'bg-orange-900 text-orange-300 border-orange-700',
  medium:   'bg-blue-900 text-blue-300 border-blue-700',
  low:      'bg-green-900 text-green-300 border-green-700',
}

interface UploadedIOC {
  id: number
  ioc: string
  type: string
  severity: string
  threat_actor: string
  mitre: string
  country: string
  source: string
}

interface UploadResult {
  parsed: number
  added: number
  skipped: number
  iocs: UploadedIOC[]
}

function UploadPanel() {
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<UploadResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFile = async (file: File) => {
    setLoading(true)
    setError(null)
    setResult(null)

    const form = new FormData()
    form.append('file', file)

    try {
      const res = await fetch(`${API_URL}/upload`, { method: 'POST', body: form })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? `Error ${res.status}`)
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setLoading(false)
    }
  }

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    e.target.value = ''
  }

  return (
    <div className="bg-slate-900 rounded-xl p-6 border border-slate-700">
      <h2 className="text-2xl font-semibold mb-5 text-orange-400">
        Import Threat Export
      </h2>

      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
          dragging
            ? 'border-orange-400 bg-orange-950/30'
            : 'border-slate-600 hover:border-orange-600 hover:bg-slate-800/50'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv,.json,.txt,.stix"
          onChange={onFileChange}
          className="hidden"
        />
        {loading ? (
          <p className="text-orange-400 animate-pulse text-sm">Parsing file...</p>
        ) : (
          <>
            <p className="text-slate-300 text-sm mb-1">
              Drag &amp; drop or <span className="text-orange-400 underline">browse</span>
            </p>
            <p className="text-slate-500 text-xs">
              Supported: .csv · .json · .stix · .txt (plain IOC list)
            </p>
          </>
        )}
      </div>

      {error && (
        <div className="mt-4 bg-red-950 border border-red-800 rounded-lg p-3 text-red-300 text-sm">
          {error}
        </div>
      )}

      {result && (
        <div className="mt-5">
          {/* Summary */}
          <div className="flex gap-4 mb-4 text-sm">
            <span className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1">
              Parsed: <strong className="text-white">{result.parsed}</strong>
            </span>
            <span className="bg-green-950 border border-green-800 rounded-lg px-3 py-1">
              Added: <strong className="text-green-300">{result.added}</strong>
            </span>
            {result.skipped > 0 && (
              <span className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-1">
                Skipped (duplicates): <strong className="text-slate-400">{result.skipped}</strong>
              </span>
            )}
          </div>

          {result.iocs.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="text-slate-400 border-b border-slate-700">
                    <th className="pb-2 pr-4">IOC</th>
                    <th className="pb-2 pr-4">Type</th>
                    <th className="pb-2 pr-4">Severity</th>
                    <th className="pb-2 pr-4">Actor</th>
                    <th className="pb-2 pr-4">MITRE</th>
                    <th className="pb-2">Country</th>
                  </tr>
                </thead>
                <tbody>
                  {result.iocs.map(ioc => (
                    <tr key={ioc.id} className="border-b border-slate-800 hover:bg-slate-800/40">
                      <td className="py-2 pr-4 font-mono text-cyan-300">{ioc.ioc}</td>
                      <td className="py-2 pr-4 text-slate-400">{ioc.type}</td>
                      <td className="py-2 pr-4">
                        <span className={`border rounded px-2 py-0.5 text-[10px] font-bold uppercase ${SEVERITY_BADGE[ioc.severity] ?? SEVERITY_BADGE.medium}`}>
                          {ioc.severity}
                        </span>
                      </td>
                      <td className="py-2 pr-4 text-slate-300">{ioc.threat_actor}</td>
                      <td className="py-2 pr-4 text-slate-400">{ioc.mitre}</td>
                      <td className="py-2 text-slate-400">{ioc.country}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-slate-500 text-sm">All IOCs were already in the feed (duplicates skipped).</p>
          )}
        </div>
      )}
    </div>
  )
}

export default UploadPanel
