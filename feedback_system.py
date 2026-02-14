"""
BEATRIX Feedback Governance System v1.0
======================================
AI-gestütztes Feedback-Management mit 4-Tier Approval-Workflow

Tier 1: Automatisch (kein Approval)
Tier 2: User wählt Lösungsoption
Tier 3: Admin Approval
Tier 4: Plattform-Owner Only

Dieses Modul wird in server.py integriert.
"""

import os
import json
import uuid
import httpx
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Text, DateTime, Integer, Float, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship

# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

class FeedbackStatus(str, Enum):
    NEU = "neu"
    TRIAGED = "triaged"
    WAITING_USER = "waiting_user"      # Tier 2: Warten auf User-Auswahl
    WAITING_ADMIN = "waiting_admin"    # Tier 3: Warten auf Admin
    WAITING_OWNER = "waiting_owner"    # Tier 4: Warten auf Owner
    IN_ARBEIT = "in_arbeit"
    TESTING = "testing"
    GELOEST = "geloest"
    ABGELEHNT = "abgelehnt"

class FeedbackCategory(str, Enum):
    BUG = "bug"
    UX = "ux"
    FEATURE = "feature"
    QUESTION = "question"
    OTHER = "other"

class FeedbackPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class FeedbackTier(int, Enum):
    AUTO = 1        # Automatisch implementieren
    USER = 2        # User wählt Option
    ADMIN = 3       # Admin Approval
    OWNER = 4       # Plattform-Owner Only

class ApprovalRequirement(str, Enum):
    NONE = "none"
    USER = "user"
    ADMIN = "admin"
    OWNER = "owner"

# Affected Areas
AFFECTED_AREAS = [
    "auth", "projects", "leads", "crm", "documents", 
    "chat", "onboarding", "dashboard", "profile", "admin", "other"
]

# Tier-Klassifizierungs-Regeln
TIER_RULES = {
    # Pattern → Tier (kann überschrieben werden)
    "typo": 1,
    "css_fix": 1,
    "tooltip": 1,
    "icon_missing": 1,
    "loading_spinner": 1,
    "date_format": 1,
    "workaround_needed": 2,
    "user_preference": 2,
    "format_choice": 2,
    "new_button": 3,
    "validation_change": 3,
    "permission_change": 3,
    "new_field": 3,
    "workflow_change": 3,
    "new_module": 4,
    "architecture": 4,
    "security": 4,
    "api_change": 4,
    "db_schema": 4,
    "external_api": 4,
    "cost_impact": 4,
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE MODELS (SQLAlchemy)
# ═══════════════════════════════════════════════════════════════════════════════

# Diese werden in server.py zu Base hinzugefügt

FEEDBACK_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS feedback (
    id VARCHAR(50) PRIMARY KEY,
    
    -- Erfassung
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Inhalt
    message TEXT NOT NULL,
    screenshot_url TEXT,
    tab_context VARCHAR(50),
    screen_size VARCHAR(20),
    browser_info TEXT,
    page_url TEXT,
    
    -- Klassifizierung
    category VARCHAR(20),
    priority VARCHAR(20),
    affected_area VARCHAR(50),
    
    -- Status & Workflow
    status VARCHAR(30) DEFAULT 'neu',
    assigned_to VARCHAR(50),
    
    -- Governance (Tier System)
    tier INTEGER,
    tier_reason TEXT,
    tier_override INTEGER,
    tier_override_by VARCHAR(50),
    tier_override_reason TEXT,
    requires_approval_from VARCHAR(20) DEFAULT 'none',
    
    -- AI-Analyse
    ai_category VARCHAR(20),
    ai_priority VARCHAR(20),
    ai_summary TEXT,
    ai_suggested_tier INTEGER,
    ai_solution_code TEXT,
    ai_solution_preview_url TEXT,
    ai_solution_confidence FLOAT,
    ai_solution_risks JSON,
    ai_related_feedback JSON,
    ai_is_duplicate_of VARCHAR(50),
    
    -- Approval-Workflow
    approved_by VARCHAR(50),
    approved_at TIMESTAMP,
    approval_note TEXT,
    rejected_reason TEXT,
    
    -- User-Choice (Tier 2)
    solution_options JSON,
    user_selected_option VARCHAR(50),
    user_selected_at TIMESTAMP,
    
    -- Resolution
    resolution_note TEXT,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(50),
    
    -- External Links
    github_issue VARCHAR(200),
    related_commit VARCHAR(100),
    
    -- Metadata
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_email);
CREATE INDEX IF NOT EXISTS idx_feedback_tier ON feedback(tier);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);
"""

FEEDBACK_COMMENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS feedback_comments (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    comment TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_comments_feedback ON feedback_comments(feedback_id);
"""

FEEDBACK_HISTORY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS feedback_history (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    changed_by VARCHAR(50),
    changed_by_email VARCHAR(320),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    field_changed VARCHAR(50),
    old_value TEXT,
    new_value TEXT,
    action_type VARCHAR(30)
);

CREATE INDEX IF NOT EXISTS idx_feedback_history_feedback ON feedback_history(feedback_id);
"""

# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS (API Request/Response)
# ═══════════════════════════════════════════════════════════════════════════════

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
    modified_code: Optional[str] = None

class FeedbackUserChoice(BaseModel):
    selected_option: str

class FeedbackComment(BaseModel):
    comment: str = Field(..., min_length=1, max_length=2000)
    is_internal: bool = False

class SolutionOption(BaseModel):
    id: str
    label: str
    description: str
    risk_level: str = "low"  # low, medium, high
    estimated_time: Optional[str] = None

class AITriageResult(BaseModel):
    category: str
    priority: str
    affected_area: str
    tier: int
    tier_reason: str
    summary: str
    suggested_solution: Optional[str] = None
    solution_confidence: Optional[float] = None
    solution_risks: Optional[List[Dict[str, str]]] = None
    related_feedback_ids: Optional[List[str]] = None
    is_duplicate_of: Optional[str] = None
    solution_options: Optional[List[SolutionOption]] = None  # For Tier 2

# ═══════════════════════════════════════════════════════════════════════════════
# AI TRIAGE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

AI_TRIAGE_SYSTEM_PROMPT = """Du bist der BEATRIX Feedback-Triage-Assistent. Analysiere User-Feedback und klassifiziere es.

## Deine Aufgabe
1. Kategorie bestimmen (bug, ux, feature, question, other)
2. Priorität bestimmen (critical, high, medium, low)
3. Betroffenen Bereich identifizieren
4. Tier für Governance bestimmen (1-4)
5. Zusammenfassung erstellen
6. Bei Tier 1-2: Lösungsvorschlag generieren

## Tier-Regeln (WICHTIG!)

### Tier 1 - AUTOMATISCH (kein Approval)
Kriterien:
- Risiko: NIEDRIG (kein Datenverlust möglich)
- Scope: Isoliert (nur 1 Komponente)
- Rollback: Sofort möglich (< 1 Minute)
- Pattern: Bekannt (Typos, CSS-Fixes, Icons, Tooltips)

### Tier 2 - USER WÄHLT
Kriterien:
- User-spezifisch (betrifft nur diesen User)
- Mehrere Lösungswege möglich
- User sollte Workaround wählen können

### Tier 3 - ADMIN APPROVAL
Kriterien:
- Multi-User (betrifft mehrere User oder öffentliche UI)
- Seiteneffekte möglich
- UI-Änderungen, Workflow-Tweaks

### Tier 4 - OWNER ONLY
Kriterien:
- Architektur-Änderungen
- Security-relevant
- Datenmodell-Änderungen
- Kosten > CHF 500
- Neue externe APIs

## Override-Regeln
- Security-relevant → Mindestens Tier 3
- Kosten > CHF 100 → Mindestens Tier 3
- Kosten > CHF 500 → Tier 4
- User-Daten betroffen → Mindestens Tier 3

## Output Format (JSON)
{
  "category": "bug|ux|feature|question|other",
  "priority": "critical|high|medium|low",
  "affected_area": "auth|projects|leads|crm|documents|chat|onboarding|dashboard|profile|admin|other",
  "tier": 1-4,
  "tier_reason": "Begründung für Tier-Wahl",
  "summary": "Kurze Zusammenfassung des Problems",
  "suggested_solution": "Code oder Beschreibung der Lösung (bei Tier 1-2)",
  "solution_confidence": 0.0-1.0,
  "solution_risks": [{"risk": "Beschreibung", "severity": "low|medium|high", "mitigation": "Wie vermeiden"}],
  "is_duplicate_of": "feedback_id oder null",
  "solution_options": [  // Nur bei Tier 2
    {"id": "a", "label": "Option A", "description": "...", "risk_level": "low"},
    {"id": "b", "label": "Option B", "description": "...", "risk_level": "medium"}
  ]
}
"""

async def ai_triage_feedback(
    message: str,
    tab_context: Optional[str],
    user_history: Optional[List[str]],
    existing_feedback: Optional[List[Dict]],
    anthropic_api_key: str,
    model: str = "claude-haiku-4-5"  # Light model for triage
) -> AITriageResult:
    """
    Führt AI-gestützte Triage des Feedbacks durch.
    Verwendet Claude Haiku für kosteneffiziente Klassifizierung.
    """
    
    # Build context
    context_parts = [f"Feedback-Nachricht: {message}"]
    
    if tab_context:
        context_parts.append(f"Tab/Kontext: {tab_context}")
    
    if user_history:
        context_parts.append(f"Bisherige Feedbacks dieses Users: {json.dumps(user_history[:5])}")
    
    if existing_feedback:
        context_parts.append(f"Ähnliche bestehende Feedbacks: {json.dumps(existing_feedback[:3])}")
    
    user_message = "\n\n".join(context_parts)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": model,
                "max_tokens": 1000,
                "system": AI_TRIAGE_SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_message}]
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Claude API error: {response.status_code}")
        
        result = response.json()
        content = result.get("content", [{}])[0].get("text", "{}")
        
        # Parse JSON response
        try:
            # Extract JSON from response (might be wrapped in markdown)
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            data = json.loads(content.strip())
            
            return AITriageResult(
                category=data.get("category", "other"),
                priority=data.get("priority", "medium"),
                affected_area=data.get("affected_area", "other"),
                tier=data.get("tier", 3),
                tier_reason=data.get("tier_reason", ""),
                summary=data.get("summary", message[:200]),
                suggested_solution=data.get("suggested_solution"),
                solution_confidence=data.get("solution_confidence"),
                solution_risks=data.get("solution_risks"),
                is_duplicate_of=data.get("is_duplicate_of"),
                solution_options=[
                    SolutionOption(**opt) for opt in data.get("solution_options", [])
                ] if data.get("solution_options") else None
            )
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            return AITriageResult(
                category="other",
                priority="medium",
                affected_area="other",
                tier=3,
                tier_reason="AI-Triage konnte nicht parsen, manuelles Review nötig",
                summary=message[:200]
            )

# ═══════════════════════════════════════════════════════════════════════════════
# TIER-SPECIFIC HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

async def handle_tier1_auto_fix(
    feedback_id: str,
    solution_code: str,
    affected_area: str,
    db_session,
    github_token: str,
    frontend_repo: str
) -> Dict[str, Any]:
    """
    Implementiert Tier 1 Fixes automatisch.
    Pusht direkt zu GitHub und deployed.
    """
    # TODO: Implementierung des Auto-Fix-Systems
    # 1. Code validieren (Syntax-Check)
    # 2. Zu GitHub pushen (Frontend oder Backend je nach affected_area)
    # 3. Vercel/Railway deployment abwarten
    # 4. Feedback-Status auf "geloest" setzen
    # 5. User benachrichtigen
    
    return {
        "success": True,
        "action": "auto_deployed",
        "commit_sha": "abc123",  # Placeholder
        "message": "Fix wurde automatisch implementiert"
    }

async def handle_tier2_user_choice(
    feedback_id: str,
    options: List[SolutionOption],
    db_session
) -> Dict[str, Any]:
    """
    Bereitet Tier 2 User-Choice vor.
    Speichert Optionen und wartet auf User-Auswahl.
    """
    # Speichere Optionen in DB
    # Setze Status auf "waiting_user"
    # Sende Notification an User
    
    return {
        "success": True,
        "action": "waiting_for_user",
        "options": [opt.dict() for opt in options],
        "message": "Bitte wähle eine Lösungsoption"
    }

async def handle_tier3_admin_approval(
    feedback_id: str,
    solution_code: str,
    solution_preview_url: Optional[str],
    db_session
) -> Dict[str, Any]:
    """
    Bereitet Tier 3 Admin-Approval vor.
    Erstellt Preview und wartet auf Admin-Freigabe.
    """
    # TODO: Vercel Preview Deployment erstellen
    # Speichere Lösung in DB
    # Setze Status auf "waiting_admin"
    # Sende Notification an Admins
    
    return {
        "success": True,
        "action": "waiting_for_admin",
        "preview_url": solution_preview_url,
        "message": "Wartet auf Admin-Freigabe"
    }

async def handle_tier4_owner_review(
    feedback_id: str,
    impact_analysis: Dict[str, Any],
    db_session
) -> Dict[str, Any]:
    """
    Bereitet Tier 4 Owner-Review vor.
    Erstellt Impact-Analyse und wartet auf Owner-Entscheidung.
    """
    # Setze Status auf "waiting_owner"
    # Sende dringende Notification an Owner
    
    return {
        "success": True,
        "action": "waiting_for_owner",
        "impact_analysis": impact_analysis,
        "message": "Wartet auf Plattform-Owner-Freigabe"
    }

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION SERVICE
# ═══════════════════════════════════════════════════════════════════════════════

async def send_feedback_notification(
    to_email: str,
    subject: str,
    template: str,
    data: Dict[str, Any],
    resend_api_key: str,
    from_email: str = "BEATRIX Feedback <feedback@bea-lab.io>"
) -> bool:
    """Sendet Email-Benachrichtigung via Resend."""
    
    # HTML Template basierend auf template-Name
    templates = {
        "feedback_received": """
            <h2>Danke für dein Feedback!</h2>
            <p>Wir haben dein Feedback erhalten und werden es bearbeiten.</p>
            <p><strong>Deine Nachricht:</strong></p>
            <blockquote>{message}</blockquote>
            <p>Feedback-ID: {feedback_id}</p>
        """,
        "feedback_resolved": """
            <h2>✅ Dein Feedback wurde bearbeitet</h2>
            <p>Dein Feedback "{summary}" wurde bearbeitet.</p>
            <p><strong>Lösung:</strong></p>
            <p>{resolution_note}</p>
            <p><a href="{app_url}">In BEATRIX öffnen</a></p>
        """,
        "feedback_options": """
            <h2>🔔 Lösungsvorschläge für dein Feedback</h2>
            <p>Für dein Feedback "{summary}" gibt es mehrere Lösungsmöglichkeiten.</p>
            <p>Bitte wähle eine Option in BEATRIX:</p>
            <p><a href="{app_url}/feedback/{feedback_id}">Optionen ansehen</a></p>
        """,
        "admin_approval_needed": """
            <h2>⏳ Feedback wartet auf Freigabe</h2>
            <p>Ein neues Feedback benötigt deine Freigabe:</p>
            <p><strong>{summary}</strong></p>
            <p>Tier: {tier} | Priorität: {priority}</p>
            <p><a href="{app_url}/admin/feedback/{feedback_id}">Jetzt prüfen</a></p>
        """
    }
    
    html_content = templates.get(template, templates["feedback_received"]).format(**data)
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "from": from_email,
                "to": to_email,
                "subject": subject,
                "html": html_content
            }
        )
        
        return response.status_code == 200

# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

async def create_github_issue(
    feedback_id: str,
    title: str,
    body: str,
    labels: List[str],
    github_token: str,
    repo: str = "FehrAdvice-Partners-AG/bea-lab-frontend"
) -> Optional[str]:
    """Erstellt GitHub Issue aus Feedback."""
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://api.github.com/repos/{repo}/issues",
            headers={
                "Authorization": f"token {github_token}",
                "Accept": "application/vnd.github.v3+json"
            },
            json={
                "title": f"[Feedback #{feedback_id[:8]}] {title}",
                "body": body,
                "labels": labels
            }
        )
        
        if response.status_code == 201:
            data = response.json()
            return data.get("html_url")
        
        return None

# ═══════════════════════════════════════════════════════════════════════════════
# STATISTICS & REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

def get_feedback_stats(db_session) -> Dict[str, Any]:
    """Berechnet Feedback-Statistiken für Dashboard."""
    
    # Diese Funktion wird die DB abfragen und Statistiken zurückgeben
    # Placeholder-Struktur:
    return {
        "total": 0,
        "by_status": {
            "neu": 0,
            "triaged": 0,
            "in_arbeit": 0,
            "geloest": 0
        },
        "by_tier": {
            1: 0,
            2: 0,
            3: 0,
            4: 0
        },
        "by_category": {
            "bug": 0,
            "ux": 0,
            "feature": 0
        },
        "avg_resolution_time_hours": 0,
        "auto_resolved_count": 0,
        "auto_resolved_percentage": 0
    }

# ═══════════════════════════════════════════════════════════════════════════════
# API ROUTES (zur Integration in server.py)
# ═══════════════════════════════════════════════════════════════════════════════

"""
Die folgenden Routes müssen in server.py hinzugefügt werden:

# === USER ENDPOINTS ===

@app.post("/api/feedback")
async def create_feedback(
    data: FeedbackCreate,
    user=Depends(require_auth)
):
    # Feedback erstellen
    # AI Triage ausführen
    # Je nach Tier: Auto-fix, User-Choice vorbereiten, oder auf Approval warten
    pass

@app.get("/api/feedback/mine")
async def get_my_feedback(user=Depends(require_auth)):
    # Alle Feedbacks des Users zurückgeben
    pass

@app.post("/api/feedback/{id}/select-option")
async def select_feedback_option(
    id: str,
    choice: FeedbackUserChoice,
    user=Depends(require_auth)
):
    # User-Auswahl für Tier 2 verarbeiten
    pass

@app.post("/api/feedback/{id}/comment")
async def add_feedback_comment(
    id: str,
    comment: FeedbackComment,
    user=Depends(require_auth)
):
    # Kommentar hinzufügen
    pass

# === ADMIN ENDPOINTS ===

@app.get("/api/admin/feedback")
async def list_all_feedback(
    status: Optional[str] = None,
    tier: Optional[int] = None,
    category: Optional[str] = None,
    user=Depends(require_permission("platform.admin_dashboard"))
):
    # Alle Feedbacks mit Filtern
    pass

@app.get("/api/admin/feedback/{id}")
async def get_feedback_detail(
    id: str,
    user=Depends(require_permission("platform.admin_dashboard"))
):
    # Feedback-Details mit History und Kommentaren
    pass

@app.patch("/api/admin/feedback/{id}")
async def update_feedback(
    id: str,
    data: FeedbackUpdate,
    user=Depends(require_permission("platform.admin_dashboard"))
):
    # Feedback aktualisieren (Status, Priority, Assignment, etc.)
    pass

@app.post("/api/admin/feedback/{id}/approve")
async def approve_feedback(
    id: str,
    approval: FeedbackApproval,
    user=Depends(require_permission("platform.admin_dashboard"))
):
    # Tier 3 Approval verarbeiten
    pass

@app.post("/api/admin/feedback/{id}/triage")
async def retriage_feedback(
    id: str,
    user=Depends(require_permission("platform.admin_dashboard"))
):
    # AI-Triage erneut ausführen
    pass

@app.post("/api/admin/feedback/{id}/github")
async def create_feedback_github_issue(
    id: str,
    user=Depends(require_permission("platform.admin_dashboard"))
):
    # GitHub Issue erstellen
    pass

@app.get("/api/admin/feedback/stats")
async def get_feedback_statistics(
    user=Depends(require_permission("platform.admin_dashboard"))
):
    # Dashboard-Statistiken
    pass

# === OWNER ENDPOINTS ===

@app.post("/api/owner/feedback/{id}/approve")
async def owner_approve_feedback(
    id: str,
    approval: FeedbackApproval,
    user=Depends(require_permission("platform.manage_settings"))
):
    # Tier 4 Owner-Approval verarbeiten
    pass
"""

print("Feedback System Module loaded successfully")
