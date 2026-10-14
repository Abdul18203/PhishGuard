import { useState } from 'react';
import './App.css';

const API = 'https://phishguard-backend-coph.onrender.com/api';

const fieldStyle = {
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
  marginBottom: 18,
};

const inputStyle = {
  width: '100%',
  boxSizing: 'border-box',
  padding: '12px 14px',
  borderRadius: 8,
  border: '1px solid #374151',
  background: '#0b1220',
  color: '#ffffff',
  fontSize: 15,
};

async function readResponse(response) {
  const text = await response.text();
  if (!text.trim()) return null;

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function responseMessage(data, fallback) {
  return typeof data === 'string' ? data : data?.message || fallback;
}

function formatScore(value) {
  if (value === null || value === undefined || value === '') {
    return 'Unavailable';
  }

  const score = Number(value);
  if (!Number.isFinite(score)) return 'Unavailable';

  return `${(Math.max(0, Math.min(1, score)) * 100).toFixed(2)}%`;
}

function formatDate(value) {
  if (!value) return 'Date unavailable';

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? 'Date unavailable'
    : date.toLocaleString();
}

function App() {
  const [token, setToken] = useState('');
  const [authMode, setAuthMode] = useState('login');
  const [authForm, setAuthForm] = useState({
    name: '',
    email: '',
    password: '',
  });

  const [authError, setAuthError] = useState('');
  const [authMessage, setAuthMessage] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [stats, setStats] = useState(null);
  const [statsError, setStatsError] = useState('');
  const [statsLoading, setStatsLoading] = useState(false);

  const [history, setHistory] = useState([]);
  const [historyError, setHistoryError] = useState('');
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyLoaded, setHistoryLoaded] = useState(false);

  async function handleAuth(event) {
    event.preventDefault();
    setAuthError('');
    setAuthMessage('');
    setAuthLoading(true);

    const isRegister = authMode === 'register';

    try {
      const response = await fetch(
        `${API}/auth/${isRegister ? 'register' : 'login'}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(
            isRegister
              ? authForm
              : {
                  email: authForm.email,
                  password: authForm.password,
                }
          ),
        }
      );

      const data = await readResponse(response);

      if (!response.ok) {
        throw new Error(
          responseMessage(data, `Request failed: HTTP ${response.status}`)
        );
      }

      if (isRegister) {
        setAuthMessage(
          'Registration successful! Please log in with your new account.'
        );
        setAuthMode('login');
        setAuthForm((previous) => ({
          ...previous,
          password: '',
        }));
      } else {
        if (typeof data !== 'string' || !data.trim()) {
          throw new Error('The server did not return a valid access token.');
        }

        const accessToken = data.trim();

        setToken(accessToken);
        setResult(null);
        setError('');
        setHistory([]);
        setHistoryError('');
        setHistoryLoaded(false);
        setStats(null);
        setStatsError('');

        void loadStats(accessToken);
      }
    } catch (err) {
      setAuthError(
        err instanceof TypeError
          ? 'Cannot connect to the backend. Check that Spring Boot is running on port 8080.'
          : err.message
      );
    } finally {
      setAuthLoading(false);
    }
  }

  function logout() {
    setToken('');
    setAuthForm({ name: '', email: '', password: '' });
    setUrl('');
    setResult(null);
    setError('');

    setStats(null);
    setStatsError('');
    setStatsLoading(false);

    setHistory([]);
    setHistoryError('');
    setHistoryLoading(false);
    setHistoryLoaded(false);

    setAuthError('');
    setAuthMessage('');
    setAuthMode('login');
  }

  async function loadStats(authToken = token) {
    if (!authToken) return;

    setStatsError('');
    setStatsLoading(true);

    try {
      const response = await fetch(`${API}/scan/history/stats`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      const data = await readResponse(response);

      if (!response.ok) {
        throw new Error(
          responseMessage(
            data,
            `Could not load dashboard statistics: HTTP ${response.status}`
          )
        );
      }

      if (!data || typeof data !== 'object') {
        throw new Error('The server returned an invalid statistics response.');
      }

      setStats(data);
    } catch (err) {
      setStatsError(
        err instanceof TypeError
          ? 'Could not connect to the backend while loading statistics.'
          : err.message
      );
    } finally {
      setStatsLoading(false);
    }
  }

  async function loadHistory() {
    if (!token || historyLoading) return;

    setHistoryError('');
    setHistoryLoading(true);

    try {
      const response = await fetch(
        `${API}/scan/history?page=0&size=10`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const data = await readResponse(response);

      if (!response.ok) {
        throw new Error(
          responseMessage(
            data,
            `Could not load history: HTTP ${response.status}`
          )
        );
      }

      const records = Array.isArray(data) ? data : data?.content || [];

      setHistory(records);
      setHistoryLoaded(true);
    } catch (err) {
      setHistoryError(
        err instanceof TypeError
          ? 'Could not connect to the backend.'
          : err.message
      );
    } finally {
      setHistoryLoading(false);
    }
  }

  async function scanUrl(event) {
    event.preventDefault();
    setResult(null);
    setError('');

    const trimmedUrl = url.trim();

    if (!trimmedUrl) {
      setError('Please enter a URL to scan.');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url: trimmedUrl }),
      });

      const data = await readResponse(response);

      if (!response.ok) {
        throw new Error(
          responseMessage(data, `Scan failed: HTTP ${response.status}`)
        );
      }

      setResult(data);

      // Update statistics without loading the history list.
      void loadStats(token);
    } catch (err) {
      setError(
        err instanceof TypeError
          ? 'Could not connect to the backend. Check that Spring Boot and the AI service are running.'
          : err.message
      );
    } finally {
      setLoading(false);
    }
  }

  if (!token) {
    return (
      <main className="app">
        <header className="topbar">
          <div className="brand">
            <span className="brand-icon">🛡</span>
            <span>PhishGuard</span>
          </div>
          <span className="status">
            <span /> AI Scanner
          </span>
        </header>

        <section className="hero">
          <div className="eyebrow">AI-POWERED URL SECURITY</div>
          <h1>
            Stay one step ahead of <span>phishing.</span>
          </h1>
          <p>
            Sign in or create an account to access your security dashboard.
          </p>

          <form
            className="auth-form"
            onSubmit={handleAuth}
            style={{
              maxWidth: 440,
              margin: '30px auto',
              padding: 28,
              border: '1px solid #303b50',
              borderRadius: 18,
              background: '#111827',
              textAlign: 'left',
            }}
          >
            <h2 style={{ marginTop: 0 }}>
              {authMode === 'login' ? 'Welcome back' : 'Create your account'}
            </h2>

            {authMode === 'register' && (
              <label style={fieldStyle}>
                Full name
                <input
                  type="text"
                  value={authForm.name}
                  onChange={(event) =>
                    setAuthForm({ ...authForm, name: event.target.value })
                  }
                  placeholder="Your name"
                  autoComplete="name"
                  minLength={2}
                  maxLength={100}
                  required
                  style={inputStyle}
                />
              </label>
            )}

            <label style={fieldStyle}>
              Email address
              <input
                type="email"
                value={authForm.email}
                onChange={(event) =>
                  setAuthForm({ ...authForm, email: event.target.value })
                }
                placeholder="you@example.com"
                autoComplete="email"
                maxLength={254}
                required
                style={inputStyle}
              />
            </label>

            <label style={fieldStyle}>
              Password
              <input
                type="password"
                value={authForm.password}
                onChange={(event) =>
                  setAuthForm({ ...authForm, password: event.target.value })
                }
                placeholder="Enter your password"
                autoComplete={
                  authMode === 'login' ? 'current-password' : 'new-password'
                }
                minLength={6}
                maxLength={72}
                required
                style={inputStyle}
              />
            </label>

            {authError && (
              <div className="message error" role="alert">
                {authError}
              </div>
            )}

            {authMessage && (
              <p role="status" style={{ color: '#86efac' }}>
                {authMessage}
              </p>
            )}

            <button
              type="submit"
              disabled={authLoading}
              style={{ width: '100%', marginTop: 12 }}
            >
              {authLoading
                ? 'Please wait...'
                : authMode === 'login'
                  ? 'Login →'
                  : 'Create Account →'}
            </button>

            <p style={{ textAlign: 'center', marginBottom: 0 }}>
              {authMode === 'login'
                ? "Don't have an account?"
                : 'Already have an account?'}{' '}
              <button
                type="button"
                onClick={() => {
                  setAuthMode(authMode === 'login' ? 'register' : 'login');
                  setAuthError('');
                  setAuthMessage('');
                }}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#93c5fd',
                  cursor: 'pointer',
                  padding: 4,
                }}
              >
                {authMode === 'login' ? 'Register' : 'Login'}
              </button>
            </p>
          </form>

          <p className="privacy-note">
            🔒 Your account is required to access the scanner.
          </p>
        </section>

        <footer>
          PhishGuard · Phishing Detection &amp; Risk Analysis Platform
        </footer>
      </main>
    );
  }

  const features = result?.features;

  return (
    <main className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-icon">🛡</span>
          <span>PhishGuard</span>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 14,
          }}
        >
          <span className="status">
            <span /> AI Scanner Online
          </span>
          <button type="button" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      <section className="hero">
        <div className="eyebrow">AI-POWERED URL SECURITY</div>
        <h1>
          Stay one step ahead of <span>phishing.</span>
        </h1>
        <p>
          Scan a URL with your machine-learning model and inspect its
          security-related characteristics.
        </p>

        <form className="scan-form" onSubmit={scanUrl}>
          <span className="link-icon">↗</span>
          <input
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="Enter a URL, e.g. https://example.com"
            aria-label="URL to scan"
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? 'Scanning...' : 'Scan URL →'}
          </button>
        </form>

        <p className="privacy-note">
          🔒 Scans are processed by your backend and AI service.
        </p>
      </section>

      {/* Dashboard statistics */}
      <section className="results">
        <div className="section-heading">
          <div>
            <div className="eyebrow">YOUR SECURITY OVERVIEW</div>
            <h2>Dashboard Statistics</h2>
          </div>
          <button
            type="button"
            onClick={() => void loadStats()}
            disabled={statsLoading}
          >
            {statsLoading ? 'Updating...' : 'Refresh Stats ↻'}
          </button>
        </div>

        {statsError && (
          <div className="message error" role="alert">
            <p>{statsError}</p>
            <button
              type="button"
              onClick={() => void loadStats()}
              disabled={statsLoading}
            >
              Try Again
            </button>
          </div>
        )}

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
            gap: 16,
            marginTop: 22,
          }}
        >
          <DashboardStat
            label="Total Scans"
            value={stats ? stats.totalScans ?? 0 : statsLoading ? '…' : '—'}
            detail="All saved scans for your account"
            accent="#93c5fd"
          />
          <DashboardStat
            label="Phishing Detected"
            value={
              stats ? stats.phishingDetected ?? 0 : statsLoading ? '…' : '—'
            }
            detail="Classified as potential phishing"
            accent="#fca5a5"
          />
          <DashboardStat
            label="Legitimate URLs"
            value={
              stats ? stats.legitimateUrls ?? 0 : statsLoading ? '…' : '—'
            }
            detail="Classified as legitimate"
            accent="#86efac"
          />
          <DashboardStat
            label="Detection Rate"
            value={
              stats
                ? `${Number(stats.detectionRate ?? 0).toFixed(2)}%`
                : statsLoading
                  ? '…'
                  : '—'
            }
            detail="Phishing share of classified scans"
            accent="#c4b5fd"
          />
        </div>
      </section>

      {error && (
        <section className="message error" role="alert">
          <strong>Scan failed</strong>
          <p>{error}</p>
        </section>
      )}

      {result && (
        <section className="results">
          <div className="section-heading">
            <div>
              <div className="eyebrow">AI SCAN REPORT</div>
              <h2>URL analysis results</h2>
            </div>
            <span className="result-badge">
              {result.model || 'AI assessment'}
            </span>
          </div>

          <div className="scanned-url">
            <span>Scanned URL</span>
            <strong>{result.url}</strong>
          </div>

          <article
            className={`prediction-card ${
              result.prediction === 'PHISHING'
                ? 'prediction-danger'
                : 'prediction-safe'
            }`}
          >
            <span className="prediction-icon">
              {result.prediction === 'PHISHING' ? '⚠️' : '🛡️'}
            </span>
            <div>
              <span>AI classification</span>
              <h2>
                {result.prediction === 'PHISHING'
                  ? 'Potential Phishing'
                  : result.prediction === 'LEGITIMATE'
                    ? 'Classified as Legitimate'
                    : 'Unknown Classification'}
              </h2>
              <p>
                {result.prediction === 'PHISHING'
                  ? 'The model identified patterns associated with phishing. Verify the URL before proceeding.'
                  : 'The model classified this URL as legitimate. This does not guarantee that the website is safe.'}
              </p>
            </div>
          </article>

          <div className="score-grid">
            <ScoreCard
              label="Phishing score"
              value={result.phishingScore}
              tone="danger"
            />
            <ScoreCard
              label="Legitimate score"
              value={result.legitimateScore}
              tone="safe"
            />
          </div>

          <p className="disclaimer">
            Model scores are not guaranteed real-world probabilities. Verify
            unfamiliar links independently.
          </p>

          {features && (
            <>
              <div className="section-heading feature-heading">
                <div>
                  <div className="eyebrow">TECHNICAL DETAILS</div>
                  <h2>Extracted URL features</h2>
                </div>
              </div>
              <div className="feature-grid">
                <Feature label="URL Length" value={features.urlLength} />
                <Feature label="Dot Count" value={features.dotCount} />
                <Feature label="Hyphen Count" value={features.hyphenCount} />
                <Feature
                  label="Special Characters"
                  value={features.specialCharacterCount}
                />
                <Feature label="Subdomains" value={features.subdomainCount} />
                <Feature
                  label="Contains @ Symbol"
                  value={features.containsAtSymbol ? 'Yes' : 'No'}
                />
                <Feature
                  label="Uses IP Address"
                  value={features.usesIpAddress ? 'Yes' : 'No'}
                />
                <Feature
                  label="Uses HTTPS"
                  value={features.usesHttps ? 'Yes' : 'No'}
                />
              </div>
            </>
          )}
        </section>
      )}

      {/* History only loads when the user clicks the button. */}
      <section className="history-section">
        <div className="section-heading">
          <div>
            <div className="eyebrow">YOUR ACTIVITY</div>
            <h2>Scan History</h2>
            <p>Load your saved scans whenever you want to review them.</p>
          </div>
          <button
            type="button"
            onClick={loadHistory}
            disabled={historyLoading}
          >
            {historyLoading
              ? 'Loading...'
              : historyLoaded
                ? 'Refresh History ↻'
                : 'Load History'}
          </button>
        </div>

        {historyError && (
          <div className="message error" role="alert">
            {historyError}
          </div>
        )}

        {!historyLoaded && !historyLoading && !historyError && (
          <p className="history-empty">
            Click “Load History” to view your saved scans.
          </p>
        )}

        {historyLoading && (
          <p className="history-empty">Loading your scan history...</p>
        )}

        {historyLoaded && history.length === 0 && !historyLoading && (
          <p className="history-empty">No saved scans found for this account.</p>
        )}

        {history.length > 0 && (
          <div className="history-list">
            {history.map((item, index) => {
              const isPhishing = item.prediction === 'PHISHING';

              return (
                <article
                  className="history-item"
                  key={item.id ?? `${item.url}-${index}`}
                >
                  <div className="history-main">
                    <strong className="history-url">
                      {item.url || 'URL unavailable'}
                    </strong>
                    <p>{formatDate(item.scannedAt)}</p>

                    <div className="history-meta">
                      <span
                        className={`history-prediction ${
                          isPhishing
                            ? 'history-phishing'
                            : 'history-legitimate'
                        }`}
                      >
                        {item.prediction === 'PHISHING'
                          ? '⚠ Potential Phishing'
                          : item.prediction === 'LEGITIMATE'
                            ? '✓ Legitimate'
                            : 'Prediction unavailable'}
                      </span>
                      <span className="history-length">
                        URL length: {item.urlLength ?? '—'}
                      </span>
                    </div>

                    <div className="history-scores">
                      <div>
                        <span>Phishing score</span>
                        <strong>{formatScore(item.phishingScore)}</strong>
                      </div>
                      <div>
                        <span>Legitimate score</span>
                        <strong>{formatScore(item.legitimateScore)}</strong>
                      </div>
                    </div>

                    <div className="history-model">
                      <span>AI model:</span> {item.model || 'Unavailable'}
                    </div>

                    <details className="history-details">
                      <summary>View URL features</summary>
                      <div className="history-feature-grid">
                        <Feature label="Dots" value={item.dotCount} />
                        <Feature label="Hyphens" value={item.hyphenCount} />
                        <Feature
                          label="Special characters"
                          value={item.specialCharacterCount}
                        />
                        <Feature
                          label="Subdomains"
                          value={item.subdomainCount}
                        />
                        <Feature
                          label="@ symbol"
                          value={item.containsAtSymbol ? 'Yes' : 'No'}
                        />
                        <Feature
                          label="IP address"
                          value={item.usesIpAddress ? 'Yes' : 'No'}
                        />
                        <Feature
                          label="HTTPS"
                          value={item.usesHttps ? 'Yes' : 'No'}
                        />
                      </div>
                    </details>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="info-grid">
        <Info
          icon="⌕"
          title="AI URL analysis"
          text="Classify URLs using your trained machine-learning model."
        />
        <Info
          icon="◷"
          title="Personal scan history"
          text="Review your own scans, classifications, scores, and technical details."
        />
        <Info
          icon="⌘"
          title="Security foundation"
          text="JWT-protected API access and user-specific scan history."
        />
      </section>

      <footer>
        PhishGuard · Phishing Detection &amp; Risk Analysis Platform
      </footer>
    </main>
  );
}

function DashboardStat({ label, value, detail, accent }) {
  return (
    <article
      style={{
        minWidth: 0,
        padding: '22px 20px',
        borderRadius: 16,
        border: '1px solid #303b50',
        background: 'linear-gradient(145deg, #111827, #0b1220)',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.14)',
      }}
    >
      <div
        style={{
          color: '#aab4c5',
          fontSize: 13,
          marginBottom: 12,
        }}
      >
        {label}
      </div>
      <div
        style={{
          color: accent,
          fontSize: 30,
          lineHeight: 1.2,
          fontWeight: 750,
          overflowWrap: 'anywhere',
        }}
      >
        {value}
      </div>
      <div
        style={{
          color: '#8b97aa',
          fontSize: 12,
          marginTop: 10,
        }}
      >
        {detail}
      </div>
    </article>
  );
}

function ScoreCard({ label, value, tone }) {
  const score = Number(value);
  const valid =
    value !== null &&
    value !== undefined &&
    value !== '' &&
    Number.isFinite(score);

  const clampedScore = valid ? Math.max(0, Math.min(1, score)) : 0;

  return (
    <article className={`score-card score-${tone}`}>
      <span>{label}</span>
      <strong>{formatScore(value)}</strong>
      <div
        className="score-track"
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clampedScore * 100}
      >
        <div
          className="score-fill"
          style={{
            width: valid ? `${clampedScore * 100}%` : '0%',
          }}
        />
      </div>
    </article>
  );
}

function Feature({ label, value }) {
  return (
    <article className="feature-card">
      <span>{label}</span>
      <strong>{String(value ?? 'Unavailable')}</strong>
    </article>
  );
}

function Info({ icon, title, text }) {
  return (
    <article className="info-card">
      <span className="info-icon">{icon}</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </article>
  );
}

export default App;
