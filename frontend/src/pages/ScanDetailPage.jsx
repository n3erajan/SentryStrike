import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  ArrowRight,
  Ban,
  Check,
  Loader2,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react'
import { useScanStatus } from '../hooks/useScanStatus.js'
import { SCAN_PHASES } from '../data/constants.js'
import { useAuth } from '../context/AuthContext.jsx'
import ErrorNotice from '../components/ErrorNotice.jsx'
import { parseUTCDate, resolveBackTarget } from '../utils/helpers.js'

const ANALYSIS_LABEL = {
  not_requested: 'Queueing AI analysis',
  queued: 'AI analysis queued',
  running: 'AI analysis running',
  completed: 'AI analysis complete',
  failed: 'AI analysis failed',
  cancelled: 'AI analysis cancelled',
}

function formatEta(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return 'N/A'
  if (seconds < 60) return `${Math.ceil(seconds)}s`
  const mins = Math.ceil(seconds / 60)
  if (mins < 60) return `${mins}m`
  const hours = Math.floor(mins / 60)
  const rem = mins % 60
  return rem ? `${hours}h ${rem}m` : `${hours}h`
}

function timeStr(iso) {
  const d = parseUTCDate(iso)
  if (!d) return '--:--:--'
  return d.toTimeString().slice(0, 8)
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname
  } catch {
    return url || 'target'
  }
}

function ScanDetailPage() {
  const { user } = useAuth()
  const { scanId } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const target = location.state?.target || ''
  const back = resolveBackTarget(location.state, '/scans', 'All scans')
  const {
    status,
    progress,
    stageIdx,
    eta,
    analysis,
    siteTitle,
    applicationName,
    targetUrl,
    statistics,
    crawlMode,
    applicationId,
    logs,
    logRef,
    error,
    active,
    cancelling,
    cancel,
  } = useScanStatus(scanId)

  const displayName =
    applicationName || siteTitle || hostnameOf(targetUrl || target)

  // Distinct URLs, SPA routes, and API endpoints the crawler has found. This is
  // discovery, not testing - nothing here says a surface was probed. Reported as
  // a dash until the crawl phase publishes a real count, rather than guessed
  // from the current stage.
  const discovered = statistics?.total_urls_crawled
  const rawFindings = statistics?.raw_findings ?? 0
  const analysisStatus = analysis?.status
  const showAnalysis = Boolean(analysisStatus) && status === 'completed'

  return (
    <div className='view'>
      <button className='back' onClick={() => navigate(back.to)}>
        ← {back.label}
      </button>
      <div className='head'>
        <div>
          <h1>Scanning {displayName || 'target'}</h1>
          <p>{targetUrl || target || `Scan ${scanId}`}</p>
        </div>
        {active && user?.role !== 'viewer' ? (
          <button className='btn danger' onClick={cancel} disabled={cancelling}>
            {cancelling ? 'Cancelling…' : 'Cancel'}
          </button>
        ) : status === 'completed' ? (
          <Link className='btn primary' to={`/report/${scanId}`}>
            <ShieldCheck className='ico' />
            View report
            <ArrowRight className='ico' />
          </Link>
        ) : status === 'failed' || status === 'cancelled' ? (
          user?.role !== 'viewer' ? (
            <Link
              className='btn primary'
              to='/scan'
              state={{
                retry: {
                  targetUrl,
                  crawlMode,
                  applicationId,
                },
              }}
            >
              <RotateCcw className='ico' />
              Retry scan
            </Link>
          ) : null
        ) : user?.role !== 'viewer' ? (
          <Link className='btn' to='/scan'>
            Start a new scan
          </Link>
        ) : null}
      </div>

      <div className='summary'>
        <div className='stat'>
          <strong>{Math.round(progress)}%</strong>
          <span>Complete</span>
        </div>
        <div className='stat'>
          <strong>{Number.isFinite(discovered) ? discovered : '-'}</strong>
          <span>URLs found</span>
        </div>
        <div className='stat'>
          <strong>{rawFindings}</strong>
          <span>Raw findings</span>
        </div>
        <div className='stat'>
          <strong>{formatEta(eta)}</strong>
          <span>Remaining</span>
        </div>
      </div>

      <div className='app-progress'>
        <span style={{ width: `${progress}%` }} />
      </div>

      <ErrorNotice
        error={error}
        title='Scan interrupted'
        className='scan-error-notice'
      />

      {showAnalysis && (
        <div className={`analysis-banner ${analysisStatus}`}>
          <div>
            <b>{ANALYSIS_LABEL[analysisStatus] || 'AI analysis'}</b>
            <span>
              {analysis.message ||
                analysis.error_message ||
                'Analyzing findings and preparing the final report.'}
            </span>
            {Number.isFinite(analysis.progress) && (
              <small>
                {analysis.progress}% complete · revision{' '}
                {analysis.revision || 1}
              </small>
            )}
          </div>
        </div>
      )}

      <div className='activity'>
        {SCAN_PHASES.slice(1).map((p, i) => {
          const idx = i + 1
          const cancelled = status === 'cancelled'
          const done = status === 'completed' || idx < stageIdx
          const cancelledPhase = cancelled && !done
          const current = active && !cancelled && idx === stageIdx
          const state = done
            ? 'Complete'
            : cancelledPhase
              ? 'Cancelled'
              : current
                ? 'Running'
                : 'Pending'
          const cls = done
            ? 'low'
            : cancelledPhase
              ? 'warn'
              : current
                ? ''
                : 'small'
          return (
            <div key={p.key}>
              <time>
                {done ? (
                  <Check size={13} />
                ) : cancelledPhase ? (
                  <Ban size={13} />
                ) : current ? (
                  <Loader2
                    size={13}
                    style={{ animation: 'spin 1s linear infinite' }}
                  />
                ) : (
                  'N/A'
                )}
              </time>
              <span>{p.label}</span>
              <b className={cls}>{state}</b>
            </div>
          )
        })}
      </div>

      <div className='panel'>
        <div className='panel-h'>Activity log</div>
        <div className='panel-b'>
          <div className='scan-log' ref={logRef}>
            {logs.length ? (
              logs.map((line, i) => (
                <div
                  key={i}
                  className={
                    line.kind === 'warn'
                      ? 'warn'
                      : line.kind === 'ok'
                        ? 'ok'
                        : ''
                  }
                >
                  [{timeStr(line.time)}] {line.text}
                </div>
              ))
            ) : (
              <div>Waiting for scanner activity…</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default ScanDetailPage
