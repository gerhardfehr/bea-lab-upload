# BEATRIX Feedback Governance System — Integration Guide

## Version 1.0.0 | 2026-02-15

---

## 📦 Was wurde erstellt?

### Frontend (FehrAdvice-Partners-AG/bea-lab-frontend)

| Datei | Beschreibung |
|-------|--------------|
| `js/feedback_system.js` | Feedback Widget + Admin Dashboard |
| `styles/feedback_admin.css` | Admin Dashboard Styles |

### Backend (FehrAdvice-Partners-AG/bea-lab-upload)

| Datei | Beschreibung |
|-------|--------------|
| `feedback_system.py` | Core Module (Models, AI Triage, Handlers) |
| `feedback_api_endpoints.py` | API Endpoints für server.py |
| `docs/migration_feedback_v1.sql` | PostgreSQL Migration Script |

---

## 🚀 Integration Steps

### Step 1: DB Migration ausführen

**Option A: Via Railway Dashboard**
1. Railway Dashboard öffnen → Projekt → PostgreSQL Service
2. "Query" Tab öffnen
3. Inhalt von `docs/migration_feedback_v1.sql` einfügen und ausführen

**Option B: Via psql CLI**
```bash
# Railway CLI installieren falls nötig
npm install -g @railway/cli

# Login und connect
railway login
railway link
railway connect postgres

# Migration ausführen
\i docs/migration_feedback_v1.sql
```

**Verify:**
```sql
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' AND table_name LIKE 'feedback%';
-- Sollte zeigen: feedback, feedback_comments, feedback_history
```

---

### Step 2: server.py erweitern

In `server.py` nach der Zeile `from sqlalchemy import ...` hinzufügen:

```python
# Feedback Pydantic Models
class FeedbackCreate(BaseModel):
    message: str = Field(..., min_length=3, max_length=2000)
    screenshot_url: Optional[str] = None
    tab_context: Optional[str] = None
    screen_size: Optional[str] = None
    browser_info: Optional[str] = None
    page_url: Optional[str] = None

class FeedbackUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    category: Optional[str] = None
    affected_area: Optional[str] = None
    assigned_to: Optional[str] = None
    tier_override: Optional[int] = None
    tier_override_reason: Optional[str] = None
    resolution_note: Optional[str] = None
    github_issue: Optional[str] = None

class FeedbackApproval(BaseModel):
    action: str = Field(..., pattern="^(approve|reject|modify)$")
    note: Optional[str] = None

class FeedbackUserChoice(BaseModel):
    selected_option: str

class FeedbackCommentCreate(BaseModel):
    comment: str = Field(..., min_length=1, max_length=2000)
    is_internal: bool = False
```

Dann die Endpoints aus `feedback_api_endpoints.py` kopieren und in server.py einfügen.

---

### Step 3: Frontend integrieren

In `index.html` vor `</body>`:

```html
<!-- Feedback System -->
<link rel="stylesheet" href="styles/feedback_admin.css">
<script src="js/feedback_system.js"></script>
```

Für die Admin-Seite (Settings/Admin Bereich):

```html
<div id="feedbackAdminContainer"></div>
<script>
    // Initialisiere Admin Dashboard wenn User Admin ist
    if (window.currentUser?.is_admin) {
        initFeedbackAdmin('feedbackAdminContainer');
    }
</script>
```

---

### Step 4: Test

1. **User-Test:** 
   - Als normaler User einloggen
   - Floating Button (💬) rechts unten sollte erscheinen
   - Feedback senden
   - Check: In `/api/feedback/mine` sollte das Feedback erscheinen

2. **Admin-Test:**
   - Als Admin einloggen
   - Settings → Feedback Management
   - Feedback sollte mit AI-Triage erscheinen
   - Status ändern, Kommentar hinzufügen, GitHub Issue erstellen

---

## 🏗️ Architektur

```
┌─────────────────────────────────────────────────────────────┐
│  USER FEEDBACK FLOW                                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  User klickt 💬  →  Modal öffnet  →  Feedback eintippen     │
│        │                                                    │
│        ▼                                                    │
│  POST /api/feedback                                         │
│        │                                                    │
│        ▼                                                    │
│  AI TRIAGE (Claude Haiku)                                   │
│  ├── Kategorie: bug/ux/feature/question/other              │
│  ├── Priorität: critical/high/medium/low                   │
│  ├── Tier: 1-4                                             │
│  └── Summary                                               │
│        │                                                    │
│        ▼                                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ TIER ROUTING                                        │   │
│  │                                                     │   │
│  │ Tier 1 → status: triaged → Auto-Fix Pipeline       │   │
│  │ Tier 2 → status: waiting_user → User wählt Option  │   │
│  │ Tier 3 → status: waiting_admin → Admin Approval    │   │
│  │ Tier 4 → status: waiting_owner → Owner Approval    │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│        │                                                    │
│        ▼                                                    │
│  Notification an User (Email via Resend)                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Tier-Klassifizierung

| Tier | Wer entscheidet | Kriterien | Status |
|------|-----------------|-----------|--------|
| 🟢 1 | Automatisch | Typos, CSS, Icons, bekannte Patterns | `triaged` |
| 🟡 2 | User | Workaround-Wahl, Format-Präferenz | `waiting_user` |
| 🟠 3 | Admin | UI-Changes, Multi-User, Workflows | `waiting_admin` |
| 🔴 4 | Owner | Architektur, Security, DB, Kosten >500 | `waiting_owner` |

---

## 🔧 Konfiguration

Die AI-Triage verwendet `ANTHROPIC_MODEL_LIGHT` (Claude Haiku) für kosteneffiziente Klassifizierung.

Environment Variables (bereits auf Railway):
- `ANTHROPIC_API_KEY` ✓
- `ANTHROPIC_MODEL_LIGHT` = `claude-haiku-4-5`
- `RESEND_API_KEY` ✓ (für Notifications)
- `GH_TOKEN` ✓ (für GitHub Issues)

---

## 📈 Metriken

Das System tracked automatisch:
- Anzahl Feedbacks pro Status/Tier/Kategorie
- Auto-resolved Rate (Tier 1)
- Durchschnittliche Resolution-Zeit
- AI Triage Accuracy (via Tier-Override Tracking)

Abrufbar via:
```
GET /api/admin/feedback/stats
```

---

## 🔜 Next Steps

1. [ ] DB Migration ausführen
2. [ ] server.py Endpoints integrieren
3. [ ] Frontend Script einbinden
4. [ ] Test mit echtem Feedback
5. [ ] Auto-Fix Pipeline für Tier 1 implementieren (Phase 2)
6. [ ] Vercel Preview für Tier 3 Approval (Phase 2)
