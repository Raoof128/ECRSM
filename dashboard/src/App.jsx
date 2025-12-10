import React, { useEffect, useState } from 'react'
import './index.css'

const streamURL = import.meta.env.VITE_EVENTS_URL || 'http://localhost:8090/events'

export default function App() {
  const [events, setEvents] = useState([])
  const [status, setStatus] = useState('disconnected')

  useEffect(() => {
    const es = new EventSource(streamURL)
    es.onopen = () => setStatus('connected')
    es.onerror = () => setStatus('error')
    es.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data)
        setEvents((cur) => [evt, ...cur].slice(0, 200))
      } catch (e) {
        console.warn('bad event', e)
      }
    }
    return () => es.close()
  }, [])

  return (
    <div className="page">
      <header>
        <div>
          <h1>Cloud Runtime Security</h1>
          <p>Live eBPF-based runtime alerts (educational demo)</p>
        </div>
        <span className={`pill ${status}`}>WS: {status}</span>
      </header>

      <section className="grid">
        <Card title="Live Alerts" full>
          <LiveTable events={events} />
        </Card>
        <Card title="Heatmap" >
          <Heatmap events={events} />
        </Card>
        <Card title="Process Lineage">
          <Lineage events={events} />
        </Card>
        <Card title="Reverse Shells">
          <ReverseShell events={events} />
        </Card>
        <Card title="Injection Attempts">
          <Injection events={events} />
        </Card>
        <Card title="CPU/Net Mini-chart">
          <MiniChart events={events} />
        </Card>
      </section>
    </div>
  )
}

function Card({ title, children, full }) {
  return (
    <div className={`card ${full ? 'full' : ''}`}>
      <h3>{title}</h3>
      {children}
    </div>
  )
}

function LiveTable({ events }) {
  if (events.length === 0) return <p className="muted">Waiting for events…</p>
  return (
    <table className="events">
      <thead>
        <tr>
          <th>Time</th>
          <th>Rule</th>
          <th>PID</th>
          <th>Comm</th>
          <th>Addr</th>
          <th>Container</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, idx) => (
          <tr key={idx}>
            <td>{new Date(e.timestamp).toLocaleTimeString()}</td>
            <td>{e.rule_id}</td>
            <td>{e.event?.PID}</td>
            <td>{trim(e.event?.Comm)}</td>
            <td>{e.event?.Addr || e.addr || ''}</td>
            <td>{e.container?.id?.slice(0, 12) || 'host'}</td>
            <td>{e.reason}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Heatmap({ events }) {
  const buckets = {}
  events.forEach((e) => {
    const pod = e.pod?.name || 'host'
    buckets[pod] = (buckets[pod] || 0) + 1
  })
  const entries = Object.entries(buckets)
  if (entries.length === 0) return <p className="muted">No data</p>
  return (
    <div className="heatmap">
      {entries.map(([pod, count]) => (
        <div key={pod} className="heat" style={{opacity: Math.min(1, 0.3 + count / 10)}}>
          <span>{pod}</span>
          <strong>{count}</strong>
        </div>
      ))}
    </div>
  )
}

function Lineage({ events }) {
  const latest = events[0]
  if (!latest) return <p className="muted">No lineage yet</p>
  return (
    <div className="lineage">
      <div className="node">PPID {latest.event?.PPID}</div>
      <div className="edge">→</div>
      <div className="node">PID {latest.event?.PID} ({trim(latest.event?.Comm)})</div>
    </div>
  )
}

function ReverseShell({ events }) {
  const shells = events.filter((e) => e.rule_id === 'reverse_shell')
  if (shells.length === 0) return <p className="muted">No detections</p>
  return shells.slice(0, 5).map((e, idx) => (
    <div key={idx} className="pill high">{trim(e.event?.Comm)} → {e.addr || e.event?.Addr}</div>
  ))
}

function Injection({ events }) {
  const inj = events.filter((e) => e.rule_id === 'process_injection')
  if (inj.length === 0) return <p className="muted">No injections observed</p>
  return inj.slice(0, 5).map((e, idx) => (
    <div key={idx} className="pill warning">{trim(e.event?.Comm)} ({e.reason})</div>
  ))
}

function MiniChart({ events }) {
  const cpu = Math.min(100, events.length * 2)
  const net = Math.min(100, events.filter((e) => e.event?.Addr).length * 5)
  return (
    <div>
      <Bar label="CPU" value={cpu} />
      <Bar label="Net" value={net} color="#22c55e" />
    </div>
  )
}

function Bar({ label, value, color = '#3b82f6' }) {
  return (
    <div className="bar">
      <span>{label}</span>
      <div className="bar-meter">
        <div className="bar-fill" style={{ width: `${value}%`, background: color }} />
      </div>
      <span className="muted">{value}%</span>
    </div>
  )
}

function trim(buf) {
  if (!buf) return ''
  if (Array.isArray(buf)) {
    return String.fromCharCode(...buf).replace(/\0/g, '').trim()
  }
  if (typeof buf === 'string') return buf
  return ''
}
