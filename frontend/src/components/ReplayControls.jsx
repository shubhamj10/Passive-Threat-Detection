import { useEffect, useState } from 'react'
import { api } from '../api/client'

const SPEEDS = [1, 5, 20, 60, 200]

export default function ReplayControls({ status, compact = false }) {
  const [files, setFiles] = useState([])
  const [file, setFile] = useState('')
  const [msg, setMsg] = useState(null)

  useEffect(() => {
    if (compact) return
    api.replayFiles().then((f) => { setFiles(f); setFile(f.find((x) => x.includes('scenario_01')) || f[0] || '') })
      .catch(() => setFiles([]))
  }, [compact])

  const run = async (fn) => {
    try { await fn(); setMsg(null) } catch (e) { setMsg(e.message.includes('409') ? 'Replay controls need the generator: start the backend with run_all.py.' : e.message) }
  }

  const state = status?.state ?? 'unavailable'
  const paused = state === 'paused'
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      {!compact ? (
        <>
          <label className="text-xs text-muted" htmlFor="replay-file">Traffic file</label>
          <select id="replay-file" value={file} onChange={(e) => setFile(e.target.value)}
            className="rounded-sm border border-rule bg-panel px-2 py-1 text-sm">
            {files.map((f) => <option key={f} value={f}>{f.replace('data/synthetic/', '')}</option>)}
          </select>
          <button onClick={() => run(() => api.replayStart(file))}
            className="rounded-sm bg-signal px-3 py-1 font-medium text-white hover:opacity-90">Replay this file</button>
        </>
      ) : null}
      <button onClick={() => run(api.replayPause)} disabled={state === 'unavailable'}
        className="rounded-sm border border-rule px-3 py-1 hover:bg-sunk disabled:opacity-40">
        {paused ? 'Resume' : 'Pause'}
      </button>
      <span className="ml-1 text-xs text-muted">Speed</span>
      {SPEEDS.map((s) => (
        <button key={s} onClick={() => run(() => api.replaySpeed(s))} disabled={state === 'unavailable'}
          aria-pressed={status?.speed === s}
          className={`rounded-sm px-2 py-1 text-xs disabled:opacity-40 ${status?.speed === s ? 'bg-ink text-panel' : 'bg-sunk hover:text-ink'}`}>
          {s}×
        </button>
      ))}
      <span className="ml-2 text-xs text-muted">{status ? `${state}, ${status.source}` : 'generator not running'}</span>
      {msg ? <p className="w-full text-xs text-sev-high">{msg}</p> : null}
    </div>
  )
}
