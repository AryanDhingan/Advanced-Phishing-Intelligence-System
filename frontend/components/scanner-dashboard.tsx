'use client'

import {
  FormEvent,
  useState,
  useRef,
} from 'react'

import {
  AlertCircle,
  ArrowUpRight,
  CheckCircle2,
  Globe2,
  Loader2,
  Radar,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  WifiOff,
} from 'lucide-react'

type BrandSimilarity = {
  brand: string
  score?: number
  domain: string
  legitimate_domain: string
  reason?: string
  is_legitimate: boolean
}

type ScanResult = {
  url: string

  prediction?: number
  ml_probability?: number
  phishing_probability?: number

  threat_score?: number
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH'

  webpage_available?: boolean
  scan_mode?: string

  flags?: string[]
  urgency_terms?: string[]

  url_intelligence_score?: number
  url_intelligence_indicators?: string[]
  suspicious_keywords?: string[]
  intelligence_explanation?: string

  brand_similarity?: BrandSimilarity | null

  title?: string
  has_password_field?: boolean

  error?: string | null
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? ''

/* =========================================================
   HELPERS
========================================================= */

function isUrlLike(value: string) {
  try {
    const url = new URL(
      value.includes('://')
        ? value
        : `https://${value}`,
    )

    return Boolean(
      url.hostname.includes('.') &&
      url.hostname.length > 3,
    )
  } catch {
    return false
  }
}

function riskClass(risk?: string) {
  if (risk === 'HIGH') return 'risk-high'
  if (risk === 'MEDIUM') return 'risk-medium'
  return 'risk-low'
}

function formatProbability(value?: number) {
  if (typeof value !== 'number') {
    return '—'
  }

  const percentage = value * 100

  if (percentage < 0.01) {
    return `${percentage.toFixed(3)}%`
  }

  return `${percentage.toFixed(1)}%`
}

function formatScore(value?: number) {
  if (typeof value !== 'number') {
    return '—'
  }

  return `${value.toFixed(2)} / 100`
}

function humanizeIndicator(value: string) {
  return value
    .replace('brand_impersonation:', 'Brand impersonation: ')
    .replace('suspicious_phrase:', 'Suspicious phrase: ')
    .replace('possible_brand_typo', 'Possible brand typo')
    .replace('brand_in_suspicious_domain', 'Brand in suspicious domain')
    .replace('legitimate_brand_domain', 'Legitimate brand domain')
    .replaceAll('_', ' ')
}

function assessmentForRisk(
  risk: 'LOW' | 'MEDIUM' | 'HIGH',
) {
  if (risk === 'HIGH') {
    return {
      title: 'High Risk — Likely Phishing',
      description:
        'Strong phishing indicators were detected. Avoid entering credentials or sensitive information.',
      icon: ShieldAlert,
    }
  }

  if (risk === 'MEDIUM') {
    return {
      title: 'Potentially Suspicious',
      description:
        'The URL contains suspicious characteristics that require caution before interacting with the website.',
      icon: ShieldAlert,
    }
  }

  return {
    title: 'Low Risk — Appears Safe',
    description:
      'No significant phishing indicators were detected by the combined security analysis.',
    icon: ShieldCheck,
  }
}

/* =========================================================
   RESULT VIEW
========================================================= */

function ScanResultView({
  result,
}: {
  result: ScanResult
}) {
  const risk = result.risk_level ?? 'LOW'

  const brandWarning =
    Boolean(result.brand_similarity) &&
    !result.brand_similarity?.is_legitimate

  const flags = result.flags ?? []
  const urgencyTerms = result.urgency_terms ?? []
  const urlIndicators =
    result.url_intelligence_indicators ?? []
  const suspiciousKeywords =
    result.suspicious_keywords ?? []

  const assessment =
    assessmentForRisk(risk)

  const AssessmentIcon =
    assessment.icon

  return (
    <section
      aria-labelledby="result-heading"
      className="glass-panel result-panel"
    >
      {/* =====================================================
          HEADER
      ===================================================== */}

      <div className="result-heading-row">
        <div>
          <p className="eyebrow">
            Analysis complete
          </p>

          <h2 id="result-heading">
            Scan Result
          </h2>
        </div>

        <span
          className={`risk-badge ${riskClass(risk)}`}
        >
          <span
            className="risk-dot"
            aria-hidden="true"
          />

          {risk} Risk
        </span>
      </div>

      {/* =====================================================
          FINAL SECURITY ASSESSMENT
      ===================================================== */}

      <div
        className={`assessment-card assessment-${risk.toLowerCase()}`}
      >
        <div className="assessment-main">
          <span className="metric-label">
            Final Security Assessment
          </span>

          <div className="assessment-title">
            <AssessmentIcon
              size={28}
              aria-hidden="true"
            />

            <span>
              {assessment.title}
            </span>
          </div>

          <p className="assessment-description">
            {assessment.description}
          </p>
        </div>

        <div className="assessment-score">
          <span className="metric-label">
            Threat Score
          </span>

          <strong>
            {formatScore(
              result.threat_score,
            )}
          </strong>
        </div>
      </div>

      {/* =====================================================
          PRIMARY METRICS
      ===================================================== */}

      <div className="metric-grid">
        <div className="metric-card">
          <span className="metric-label">
            Phishing Probability
          </span>

          <strong>
            {formatProbability(
              result.phishing_probability,
            )}
          </strong>

          <span className="metric-description">
            Intelligence-fused confidence
          </span>
        </div>

        <div className="metric-card">
          <span className="metric-label">
            Threat Score
          </span>

          <strong>
            {formatScore(
              result.threat_score,
            )}
          </strong>

          <span className="metric-description">
            Overall security threat level
          </span>
        </div>

        <div className="metric-card">
          <span className="metric-label">
            URL Intelligence Score
          </span>

          <strong>
            {formatScore(
              result.url_intelligence_score,
            )}
          </strong>

          <span className="metric-description">
            URL-level threat indicators
          </span>
        </div>

        <div className="metric-card">
          <span className="metric-label">
            ML Probability
          </span>

          <strong>
            {formatProbability(
              result.ml_probability,
            )}
          </strong>

          <span className="metric-description">
            Raw machine-learning output
          </span>
        </div>
      </div>

      {/* =====================================================
          TECHNICAL DETAILS
      ===================================================== */}

      <div className="secondary-info-grid">
        <div className="info-card">
          <span className="metric-label">
            ML Classification
          </span>

          <strong>
            {result.prediction === 1
              ? 'Phishing'
              : 'Legitimate'}
          </strong>

          <span className="info-description">
            Raw ML model prediction
          </span>
        </div>

        <div className="info-card">
          <span className="metric-label">
            Detection Mode
          </span>

          <strong>
            {result.scan_mode ?? '—'}
          </strong>

          <span className="info-description">
            Analysis pipeline used
          </span>
        </div>

        <div className="info-card">
          <span className="metric-label">
            Webpage Availability
          </span>

          <strong>
            {result.webpage_available
              ? 'Available'
              : 'Unavailable'}
          </strong>

          <span className="info-description">
            Website accessibility during scan
          </span>
        </div>
      </div>

      {/* =====================================================
          URL
      ===================================================== */}

      <div className="section-divider" />

      <div className="url-display">
        <Globe2
          size={17}
          aria-hidden="true"
        />

        <code>{result.url}</code>

        <ArrowUpRight
          size={16}
          aria-hidden="true"
        />
      </div>

      {/* =====================================================
          WEBPAGE NOTICES
      ===================================================== */}

      {result.scan_mode === 'URL_ONLY' && (
        <div className="notice notice-info">
          <WifiOff
            size={17}
            aria-hidden="true"
          />

          <span>
            Webpage unavailable. URL-only
            analysis was performed.
          </span>
        </div>
      )}

      {result.error &&
        result.scan_mode !== 'URL_ONLY' && (
          <div className="notice notice-info">
            <AlertCircle
              size={17}
              aria-hidden="true"
            />

            <span>
              Could not fetch the webpage.
              Available URL analysis is shown
              below.
            </span>
          </div>
        )}

      {/* =====================================================
          WEBPAGE INFORMATION
      ===================================================== */}

      {result.title && (
        <div className="page-info-card">
          <span className="metric-label">
            Page Title
          </span>

          <p>{result.title}</p>
        </div>
      )}

      {result.has_password_field && (
        <div className="password-warning">
          <ShieldAlert
            size={18}
            aria-hidden="true"
          />

          <div>
            <strong>
              Password Field Detected
            </strong>

            <span>
              This webpage contains a
              password input field.
            </span>
          </div>
        </div>
      )}

      {/* =====================================================
          INTELLIGENCE ASSESSMENT
      ===================================================== */}

      {result.intelligence_explanation && (
        <div className="intelligence-card">
          <div className="section-heading">
            <span className="metric-label">
              Intelligence Assessment
            </span>
          </div>

          <p>
            {result.intelligence_explanation}
          </p>
        </div>
      )}

      {/* =====================================================
          URL INTELLIGENCE
      ===================================================== */}

      {(urlIndicators.length > 0 ||
        suspiciousKeywords.length > 0) && (
          <div className="intelligence-card">
            <div className="section-heading">
              <span className="metric-label">
                URL Intelligence
              </span>

              {typeof result.url_intelligence_score ===
                'number' && (
                  <span className="section-score">
                    {formatScore(
                      result.url_intelligence_score,
                    )}
                  </span>
                )}
            </div>

            {urlIndicators.length > 0 && (
              <div className="intel-section">
                <span className="intel-subtitle">
                  Indicators
                </span>

                <div className="tag-list">
                  {urlIndicators.map(
                    (indicator, index) => (
                      <span
                        className="tag"
                        key={`${indicator}-${index}`}
                      >
                        {humanizeIndicator(
                          indicator,
                        )}
                      </span>
                    ),
                  )}
                </div>
              </div>
            )}

            {suspiciousKeywords.length > 0 && (
              <div className="intel-section">
                <span className="intel-subtitle">
                  Suspicious Keywords
                </span>

                <div className="tag-list">
                  {suspiciousKeywords.map(
                    (keyword, index) => (
                      <span
                        className="tag tag-warning"
                        key={`${keyword}-${index}`}
                      >
                        {keyword}
                      </span>
                    ),
                  )}
                </div>
              </div>
            )}
          </div>
        )}

      {/* =====================================================
          DETECTION SIGNALS
      ===================================================== */}

      {(flags.length > 0 ||
        urgencyTerms.length > 0) && (
          <div className="intelligence-card">
            <div className="section-heading">
              <span className="metric-label">
                Detection Signals
              </span>
            </div>

            <div className="tag-list">
              {flags.map(
                (flag, index) => (
                  <span
                    className="tag"
                    key={`${flag}-${index}`}
                  >
                    {humanizeIndicator(flag)}
                  </span>
                ),
              )}

              {urgencyTerms.map(
                (term, index) => (
                  <span
                    className="tag tag-warning"
                    key={`urgency-${term}-${index}`}
                  >
                    Urgency: {term}
                  </span>
                ),
              )}
            </div>
          </div>
        )}

      {/* =====================================================
          BRAND IMPERSONATION
      ===================================================== */}

      {result.brand_similarity && (
        <div
          className={`brand-card ${brandWarning
            ? 'brand-warning'
            : 'brand-safe'
            }`}
        >
          <div className="brand-card-heading">
            {brandWarning ? (
              <ShieldAlert
                size={19}
                aria-hidden="true"
              />
            ) : (
              <CheckCircle2
                size={19}
                aria-hidden="true"
              />
            )}

            <span>
              {brandWarning
                ? 'Possible Brand Impersonation'
                : 'Brand Match'}
            </span>
          </div>

          <div className="brand-values">
            <div className="brand-value">
              <span className="metric-label">
                Brand
              </span>

              <code>
                {result.brand_similarity.brand}
              </code>
            </div>

            <div className="brand-value">
              <span className="metric-label">
                Detected Domain
              </span>

              <code>
                {result.brand_similarity.domain}
              </code>
            </div>

            <div className="brand-value">
              <span className="metric-label">
                Legitimate Domain
              </span>

              <code>
                {
                  result.brand_similarity
                    .legitimate_domain
                }
              </code>
            </div>

            <div className="brand-value">
              <span className="metric-label">
                Detection Reason
              </span>

              <span>
                {result.brand_similarity.reason
                  ? humanizeIndicator(
                    result.brand_similarity
                      .reason,
                  )
                  : 'Brand similarity detected'}
              </span>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

/* =========================================================
   MAIN DASHBOARD
========================================================= */

export function ScannerDashboard() {
  const [url, setUrl] = useState('')
  const [result, setResult] =
    useState<ScanResult | null>(null)

  const [validationError, setValidationError] =
    useState('')

  const [networkError, setNetworkError] =
    useState(false)

  const [loading, setLoading] =
    useState(false)

  const headerRef = useRef<HTMLElement | null>(null)

  function handleHeaderMouseMove(
    event: React.MouseEvent<HTMLElement>,
  ) {
    const header = headerRef.current

    if (!header) return

    const rect = header.getBoundingClientRect()

    header.style.setProperty(
      '--mouse-x',
      `${event.clientX - rect.left}px`,
    )

    header.style.setProperty(
      '--mouse-y',
      `${event.clientY - rect.top}px`,
    )
  }

  async function scanUrl(
    event?: FormEvent,
  ) {
    event?.preventDefault()

    setValidationError('')
    setNetworkError(false)
    setResult(null)

    const normalized = url.trim()

    if (
      !normalized ||
      !isUrlLike(normalized)
    ) {
      setValidationError(
        'Enter a valid URL, including a domain name.',
      )

      return
    }

    setLoading(true)

    const controller =
      new AbortController()

    const timeout = window.setTimeout(
      () => controller.abort(),
      30000,
    )

    try {
      const response = await fetch(
        `${API_BASE}/api/scan`,
        {
          method: 'POST',
          headers: {
            'Content-Type':
              'application/json',
          },
          body: JSON.stringify({
            url: normalized,
          }),
          signal: controller.signal,
        },
      )

      const data =
        (await response.json()) as ScanResult

      if (!response.ok) {
        setValidationError(
          'The scanning service returned an error. Please check the URL and try again.',
        )

        return
      }

      if (
        data.error === 'Invalid URL' &&
        !data.risk_level
      ) {
        setValidationError(
          'The scanning service could not validate this URL. Check it and try again.',
        )
      } else {
        setResult(data)
      }
    } catch (error) {
      /*
        AbortError is expected when the 30-second
        timeout expires. Do not show a noisy console
        error for it.
      */

      if (
        error instanceof DOMException &&
        error.name === 'AbortError'
      ) {
        setNetworkError(true)
        return
      }

      if (
        error instanceof Error &&
        error.name === 'AbortError'
      ) {
        setNetworkError(true)
        return
      }

      console.error(
        'Scan request failed:',
        error,
      )

      setNetworkError(true)
    } finally {
      window.clearTimeout(timeout)
      setLoading(false)
    }
  }

  return (
    <main className="scanner-shell">
      {/* =====================================================
          HEADER
      ===================================================== */}

      <header
        ref={headerRef}
        className="app-header"
        onMouseMove={handleHeaderMouseMove}
      >
        <div className="header-cursor-glow" />

        <div className="brand-mark">
          <Radar
            size={18}
            aria-hidden="true"
          />

          <span>
            Phishing Intelligence System
          </span>
        </div>

        <span className="status-pill">
          <span aria-hidden="true" />

          Scanner ready
        </span>
      </header>

      <div className="scanner-content">
        {/* ===================================================
            INTRO
        =================================================== */}

        <section className="intro">
          <p className="eyebrow">
            URL Threat Analysis
          </p>

          <h1>
            Inspect a link before
            <br />
            <em>it becomes a risk.</em>
          </h1>

          <p className="intro-copy">
            Analyze suspicious URLs using
            machine learning, URL intelligence,
            webpage signals, and phishing
            indicators.
          </p>
        </section>

        {/* ===================================================
            SCANNER FORM
        =================================================== */}

        <form
          className="scan-form glass-panel"
          onSubmit={scanUrl}
          noValidate
        >
          <label htmlFor="url">
            URL to scan
          </label>

          <div className="input-row">
            <div className="input-wrap">
              <Globe2
                size={18}
                aria-hidden="true"
              />

              <input
                id="url"
                type="text"
                inputMode="url"
                placeholder="https://example.com"
                value={url}
                onChange={(event) =>
                  setUrl(
                    event.target.value,
                  )
                }
                aria-describedby={
                  validationError
                    ? 'url-error'
                    : undefined
                }
                aria-invalid={Boolean(
                  validationError,
                )}
              />

              <kbd>
                ⌘ ↵
              </kbd>
            </div>

            <button
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2
                    size={17}
                    className="spin"
                  />

                  Scanning
                </>
              ) : (
                <>
                  <Radar size={17} />

                  Scan URL
                </>
              )}
            </button>
          </div>

          {validationError && (
            <p
              id="url-error"
              className="form-error"
              role="alert"
            >
              <AlertCircle size={15} />

              {validationError}
            </p>
          )}
        </form>

        {/* ===================================================
            LOADING
        =================================================== */}

        {loading && (
          <div
            className="loading-state glass-panel"
            role="status"
          >
            <div className="loading-icon">
              <Loader2
                className="spin"
                size={22}
              />
            </div>

            <div>
              <strong>
                Analyzing URL signals
              </strong>

              <span>
                Checking page availability,
                URL intelligence, and threat
                indicators…
              </span>
            </div>
          </div>
        )}

        {/* ===================================================
            NETWORK ERROR
        =================================================== */}

        {networkError && (
          <div
            className="error-state glass-panel"
            role="alert"
          >
            <div className="error-icon">
              <WifiOff size={20} />
            </div>

            <div>
              <strong>
                Unable to reach the scanning
                service
              </strong>

              <span>
                Check that the backend is
                running, then try again.
              </span>
            </div>

            <button
              type="button"
              onClick={() => scanUrl()}
            >
              <RefreshCw size={16} />

              Retry
            </button>
          </div>
        )}

        {/* ===================================================
            RESULT
        =================================================== */}

        {result && (
          <ScanResultView
            result={result}
          />
        )}
      </div>

      {/* =====================================================
          FOOTER
      ===================================================== */}

      <footer>
        <span>
          Single URL analysis
        </span>

        <span>•</span>

        <span>
          FastAPI service
        </span>

        <span>•</span>

        <span>
          ML + Intelligence Fusion
        </span>
      </footer>
    </main>
  )
}

export default ScannerDashboard