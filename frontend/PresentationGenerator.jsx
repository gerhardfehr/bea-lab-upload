/**
 * BEATRIX Auto-Presentation Button
 * 
 * Integration: Add this component to the documents list or sidebar in the BEATRIX frontend.
 * 
 * Usage:
 *   <PresentationGenerator 
 *     selectedDocIds={selectedDocs} 
 *     apiBase="https://bea-lab-upload-production.up.railway.app"
 *     token={authToken}
 *   />
 */

// ─── MODAL COMPONENT ──────────────────────────────────────────────────────────
function PresentationGenerator({ selectedDocIds = [], apiBase, token }) {
  const [isOpen, setIsOpen] = React.useState(false);
  const [isLoading, setIsLoading] = React.useState(false);
  const [progress, setProgress] = React.useState('');
  const [error, setError] = React.useState(null);

  const [form, setForm] = React.useState({
    title: '',
    template: 'client_pitch',
    language: 'de',
    content: '',
    max_slides: 8
  });

  const templates = [
    { value: 'client_pitch',     label: '📊 Client Pitch',     desc: 'Executive Summary für Kunden' },
    { value: 'research_report',  label: '🔬 Research Report',  desc: 'BCM/Paper-basiert, wissenschaftlich' },
    { value: 'workshop',         label: '🎯 Workshop',          desc: 'Interaktiv mit BCM/EBF Framework' },
    { value: 'internal',         label: '📋 Internal Report',  desc: 'Team-Update & Projektfortschritt' },
  ];

  async function handleGenerate() {
    if (!form.title.trim()) {
      setError('Bitte einen Titel eingeben.');
      return;
    }

    setIsLoading(true);
    setError(null);
    setProgress('Claude strukturiert Slides...');

    try {
      const body = {
        title: form.title,
        template: form.template,
        language: form.language,
        max_slides: parseInt(form.max_slides),
        content: form.content || null,
        doc_ids: selectedDocIds.length > 0 ? selectedDocIds : null
      };

      setProgress('Erstelle .pptx im FehrAdvice Design...');

      const response = await fetch(`${apiBase}/api/presentations/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Fehler ${response.status}`);
      }

      setProgress('Download wird vorbereitet...');

      // Trigger download
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const safeTitle = form.title.replace(/[^a-zA-Z0-9\s-_]/g, '').substring(0, 50);
      const date = new Date().toISOString().split('T')[0].replace(/-/g, '');
      a.href = url;
      a.download = `BEATRIX_${safeTitle}_${date}.pptx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setIsOpen(false);
      setProgress('');
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <>
      {/* ── Trigger Button ── */}
      <button
        onClick={() => setIsOpen(true)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '8px 16px',
          backgroundColor: '#024079',
          color: '#fff',
          border: 'none',
          borderRadius: '6px',
          fontSize: '13px',
          fontWeight: '600',
          cursor: 'pointer',
          transition: 'background 0.2s',
        }}
        onMouseEnter={e => e.target.style.backgroundColor = '#549EDE'}
        onMouseLeave={e => e.target.style.backgroundColor = '#024079'}
        title="Präsentation generieren"
      >
        <span>📊</span>
        <span>Präsentation erstellen</span>
        {selectedDocIds.length > 0 && (
          <span style={{
            background: '#549EDE',
            borderRadius: '10px',
            padding: '1px 7px',
            fontSize: '11px'
          }}>
            {selectedDocIds.length}
          </span>
        )}
      </button>

      {/* ── Modal ── */}
      {isOpen && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          background: 'rgba(2, 64, 121, 0.5)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: '20px'
        }}
          onClick={e => { if (e.target === e.currentTarget && !isLoading) setIsOpen(false); }}
        >
          <div style={{
            background: '#fff',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '520px',
            padding: '28px',
            boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
            fontFamily: 'system-ui, -apple-system, sans-serif'
          }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div>
                <h2 style={{ margin: 0, fontSize: '18px', color: '#024079', fontWeight: 700 }}>
                  📊 Präsentation generieren
                </h2>
                <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#7EBDAC' }}>
                  FehrAdvice Corporate Identity  ·  Powered by Claude
                </p>
              </div>
              {!isLoading && (
                <button onClick={() => setIsOpen(false)}
                  style={{ background: 'none', border: 'none', fontSize: '20px', cursor: 'pointer', color: '#888' }}>
                  ×
                </button>
              )}
            </div>

            {/* Form */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

              {/* Title */}
              <div>
                <label style={labelStyle}>Titel *</label>
                <input
                  type="text"
                  value={form.title}
                  onChange={e => setForm({ ...form, title: e.target.value })}
                  placeholder="z.B. BEATRIX Projektupdate Q1 2026"
                  disabled={isLoading}
                  style={inputStyle}
                />
              </div>

              {/* Template */}
              <div>
                <label style={labelStyle}>Template</label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                  {templates.map(t => (
                    <button
                      key={t.value}
                      onClick={() => setForm({ ...form, template: t.value })}
                      disabled={isLoading}
                      style={{
                        padding: '10px 12px',
                        border: `2px solid ${form.template === t.value ? '#024079' : '#e5e7eb'}`,
                        borderRadius: '8px',
                        background: form.template === t.value ? '#f0f5fb' : '#fff',
                        cursor: 'pointer',
                        textAlign: 'left',
                        transition: 'all 0.15s'
                      }}
                    >
                      <div style={{ fontSize: '12px', fontWeight: 600, color: '#024079' }}>{t.label}</div>
                      <div style={{ fontSize: '10px', color: '#888', marginTop: '2px' }}>{t.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Language + Slides row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={labelStyle}>Sprache</label>
                  <select value={form.language} onChange={e => setForm({ ...form, language: e.target.value })}
                    disabled={isLoading} style={inputStyle}>
                    <option value="de">🇩🇪 Deutsch</option>
                    <option value="en">🇬🇧 English</option>
                  </select>
                </div>
                <div>
                  <label style={labelStyle}>Max. Slides</label>
                  <select value={form.max_slides} onChange={e => setForm({ ...form, max_slides: e.target.value })}
                    disabled={isLoading} style={inputStyle}>
                    {[4, 6, 8, 10, 12].map(n => (
                      <option key={n} value={n}>{n} Slides</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Optional content */}
              <div>
                <label style={labelStyle}>
                  Zusätzlicher Inhalt
                  <span style={{ fontWeight: 400, color: '#aaa' }}> (optional)</span>
                </label>
                <textarea
                  value={form.content}
                  onChange={e => setForm({ ...form, content: e.target.value })}
                  placeholder="Stichpunkte, Kernbotschaften, Daten..."
                  disabled={isLoading}
                  rows={3}
                  style={{ ...inputStyle, resize: 'vertical', minHeight: '72px' }}
                />
              </div>

              {/* Selected docs info */}
              {selectedDocIds.length > 0 && (
                <div style={{
                  background: '#f0f5fb', borderRadius: '8px', padding: '10px 14px',
                  fontSize: '12px', color: '#024079', display: 'flex', alignItems: 'center', gap: '8px'
                }}>
                  📄 <strong>{selectedDocIds.length} Dokument{selectedDocIds.length > 1 ? 'e' : ''}</strong> aus BEATRIX werden eingebettet
                </div>
              )}

              {/* Error */}
              {error && (
                <div style={{
                  background: '#fff0f0', border: '1px solid #fca5a5',
                  borderRadius: '8px', padding: '10px 14px',
                  fontSize: '12px', color: '#dc2626'
                }}>
                  ⚠️ {error}
                </div>
              )}

              {/* Progress */}
              {isLoading && (
                <div style={{
                  background: '#f0f5fb', borderRadius: '8px', padding: '12px 14px',
                  fontSize: '12px', color: '#024079',
                  display: 'flex', alignItems: 'center', gap: '10px'
                }}>
                  <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>⚙️</span>
                  {progress}
                </div>
              )}

              {/* Actions */}
              <div style={{ display: 'flex', gap: '10px', marginTop: '4px' }}>
                {!isLoading && (
                  <button onClick={() => setIsOpen(false)}
                    style={{ ...btnStyle, background: '#f3f4f6', color: '#374151', flex: 1 }}>
                    Abbrechen
                  </button>
                )}
                <button
                  onClick={handleGenerate}
                  disabled={isLoading || !form.title.trim()}
                  style={{
                    ...btnStyle,
                    background: isLoading ? '#a0b4c8' : '#024079',
                    color: '#fff',
                    flex: 2,
                    cursor: isLoading ? 'not-allowed' : 'pointer'
                  }}
                >
                  {isLoading ? '⚙️  Generiert...' : '📊  Präsentation erstellen'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </>
  );
}

// ─── STYLES ───────────────────────────────────────────────────────────────────
const labelStyle = {
  display: 'block',
  fontSize: '12px',
  fontWeight: 600,
  color: '#374151',
  marginBottom: '6px'
};

const inputStyle = {
  width: '100%',
  padding: '8px 12px',
  border: '1px solid #d1d5db',
  borderRadius: '6px',
  fontSize: '13px',
  color: '#374151',
  outline: 'none',
  boxSizing: 'border-box',
  fontFamily: 'inherit'
};

const btnStyle = {
  padding: '10px 16px',
  border: 'none',
  borderRadius: '8px',
  fontSize: '13px',
  fontWeight: 600,
  cursor: 'pointer',
  transition: 'all 0.15s'
};

// ─── EXPORT ───────────────────────────────────────────────────────────────────
// For use in BEATRIX frontend (React/JSX):
// export default PresentationGenerator;

// For vanilla JS integration in index.html, add:
// <div id="presentation-btn"></div>
// ReactDOM.render(
//   <PresentationGenerator apiBase="https://bea-lab-upload-production.up.railway.app" token={getToken()} />,
//   document.getElementById('presentation-btn')
// );
