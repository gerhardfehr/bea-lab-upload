"""
BEATRIX Feedback Governance System — API Endpoints
===================================================
Diese Datei enthält die API-Endpoints die in server.py integriert werden müssen.

INTEGRATION:
1. Feedback-Tabellen bei Startup erstellen (in get_db())
2. Pydantic Models importieren
3. Endpoints zu FastAPI app hinzufügen
"""

import uuid
import json
import httpx
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
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

class FeedbackCommentCreate(BaseModel):
    comment: str = Field(..., min_length=1, max_length=2000)
    is_internal: bool = False

# ═══════════════════════════════════════════════════════════════════════════════
# DB SCHEMA (add to get_db() startup)
# ═══════════════════════════════════════════════════════════════════════════════

FEEDBACK_TABLES_SQL = """
-- Feedback main table
CREATE TABLE IF NOT EXISTS feedback (
    id VARCHAR(50) PRIMARY KEY,
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message TEXT NOT NULL,
    screenshot_url TEXT,
    tab_context VARCHAR(50),
    screen_size VARCHAR(20),
    browser_info TEXT,
    page_url TEXT,
    category VARCHAR(20),
    priority VARCHAR(20),
    affected_area VARCHAR(50),
    status VARCHAR(30) DEFAULT 'neu',
    assigned_to VARCHAR(50),
    tier INTEGER,
    tier_reason TEXT,
    tier_override INTEGER,
    tier_override_by VARCHAR(50),
    tier_override_reason TEXT,
    requires_approval_from VARCHAR(20) DEFAULT 'none',
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
    approved_by VARCHAR(50),
    approved_at TIMESTAMP,
    approval_note TEXT,
    rejected_reason TEXT,
    solution_options JSON,
    user_selected_option VARCHAR(50),
    user_selected_at TIMESTAMP,
    resolution_note TEXT,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(50),
    github_issue VARCHAR(200),
    related_commit VARCHAR(100),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_email);

-- Feedback comments
CREATE TABLE IF NOT EXISTS feedback_comments (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL,
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    comment TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Feedback history
CREATE TABLE IF NOT EXISTS feedback_history (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL,
    changed_by VARCHAR(50),
    changed_by_email VARCHAR(320),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    field_changed VARCHAR(50),
    old_value TEXT,
    new_value TEXT,
    action_type VARCHAR(30)
);
"""

# ═══════════════════════════════════════════════════════════════════════════════
# AI TRIAGE PROMPT
# ═══════════════════════════════════════════════════════════════════════════════

AI_TRIAGE_SYSTEM_PROMPT = """Du bist der BEATRIX Feedback-Triage-Assistent. Analysiere User-Feedback und klassifiziere es.

## Deine Aufgabe
1. Kategorie bestimmen (bug, ux, feature, question, other)
2. Priorität bestimmen (critical, high, medium, low)
3. Betroffenen Bereich identifizieren
4. Tier für Governance bestimmen (1-4)
5. Zusammenfassung erstellen

## Tier-Regeln

### Tier 1 - AUTOMATISCH
- Typos, CSS-Fixes, Icons, Tooltips
- Bekannte Patterns, sofort rollback-fähig

### Tier 2 - USER WÄHLT
- User-spezifisch, mehrere Lösungswege möglich

### Tier 3 - ADMIN APPROVAL
- Multi-User UI-Changes, Workflow-Änderungen

### Tier 4 - OWNER ONLY
- Architektur, Security, DB-Schema, Kosten >500 CHF

## Output (JSON only, no markdown):
{"category":"bug","priority":"high","affected_area":"projects","tier":3,"tier_reason":"Multi-User betroffen","summary":"Kurze Zusammenfassung"}
"""

async def ai_triage_feedback(message: str, tab_context: str, api_key: str, model: str = "claude-haiku-4-5"):
    """AI-gestützte Klassifizierung des Feedbacks."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": model,
                    "max_tokens": 500,
                    "system": AI_TRIAGE_SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": f"Feedback: {message}\nKontext: {tab_context or 'unbekannt'}"}]
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get("content", [{}])[0].get("text", "{}")
                # Clean JSON
                if "```" in content:
                    content = content.split("```")[1].replace("json", "").strip()
                return json.loads(content)
    except Exception as e:
        print(f"AI Triage error: {e}")
    
    # Fallback
    return {
        "category": "other",
        "priority": "medium", 
        "affected_area": "other",
        "tier": 3,
        "tier_reason": "Manuelles Review erforderlich",
        "summary": message[:200]
    }

# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS (copy into server.py)
# ═══════════════════════════════════════════════════════════════════════════════

"""
# ══════════════════════════════════════════════════════════════════════════════
# FEEDBACK ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/feedback")
async def create_feedback(data: FeedbackCreate, user=Depends(require_auth)):
    \"\"\"Create new feedback with AI triage.\"\"\"
    db = get_db()
    session = db()
    try:
        feedback_id = str(uuid.uuid4())
        
        # AI Triage
        triage = await ai_triage_feedback(
            data.message, 
            data.tab_context,
            ANTHROPIC_API_KEY,
            ANTHROPIC_MODEL_LIGHT
        )
        
        # Determine approval requirement based on tier
        approval_map = {1: "none", 2: "user", 3: "admin", 4: "owner"}
        status_map = {1: "triaged", 2: "waiting_user", 3: "waiting_admin", 4: "waiting_owner"}
        
        tier = triage.get("tier", 3)
        
        session.execute(text(\"\"\"
            INSERT INTO feedback (
                id, user_id, user_email, message, screenshot_url, tab_context,
                screen_size, browser_info, page_url, category, priority, 
                affected_area, status, tier, tier_reason, requires_approval_from,
                ai_category, ai_priority, ai_summary, ai_suggested_tier
            ) VALUES (
                :id, :user_id, :email, :message, :screenshot, :tab,
                :screen, :browser, :url, :category, :priority,
                :area, :status, :tier, :reason, :approval,
                :ai_cat, :ai_pri, :ai_sum, :ai_tier
            )
        \"\"\"), {
            "id": feedback_id,
            "user_id": user.get("user_id"),
            "email": user.get("sub"),
            "message": data.message,
            "screenshot": data.screenshot_url,
            "tab": data.tab_context,
            "screen": data.screen_size,
            "browser": data.browser_info,
            "url": data.page_url,
            "category": triage.get("category"),
            "priority": triage.get("priority"),
            "area": triage.get("affected_area"),
            "status": status_map.get(tier, "waiting_admin"),
            "tier": tier,
            "reason": triage.get("tier_reason"),
            "approval": approval_map.get(tier, "admin"),
            "ai_cat": triage.get("category"),
            "ai_pri": triage.get("priority"),
            "ai_sum": triage.get("summary"),
            "ai_tier": tier
        })
        session.commit()
        
        # Log creation
        session.execute(text(\"\"\"
            INSERT INTO feedback_history (id, feedback_id, changed_by_email, action_type)
            VALUES (:id, :fid, :email, 'created')
        \"\"\"), {"id": str(uuid.uuid4()), "fid": feedback_id, "email": user.get("sub")})
        session.commit()
        
        return {
            "id": feedback_id,
            "tier": tier,
            "status": status_map.get(tier),
            "message": "Feedback erfolgreich erstellt",
            "ai_summary": triage.get("summary")
        }
        
    finally:
        session.close()


@app.get("/api/feedback/mine")
async def get_my_feedback(user=Depends(require_auth)):
    \"\"\"Get all feedbacks submitted by current user.\"\"\"
    db = get_db()
    session = db()
    try:
        result = session.execute(text(\"\"\"
            SELECT id, message, status, tier, category, priority, 
                   ai_summary, solution_options, user_selected_option,
                   resolution_note, created_at, updated_at
            FROM feedback 
            WHERE user_email = :email 
            ORDER BY created_at DESC
            LIMIT 50
        \"\"\"), {"email": user.get("sub")})
        
        feedbacks = []
        for row in result:
            feedbacks.append({
                "id": row[0],
                "message": row[1][:200] + "..." if len(row[1]) > 200 else row[1],
                "status": row[2],
                "tier": row[3],
                "category": row[4],
                "priority": row[5],
                "ai_summary": row[6],
                "solution_options": json.loads(row[7]) if row[7] else None,
                "user_selected_option": row[8],
                "resolution_note": row[9],
                "created_at": row[10].isoformat() if row[10] else None,
                "updated_at": row[11].isoformat() if row[11] else None
            })
        
        return feedbacks
        
    finally:
        session.close()


@app.post("/api/feedback/{feedback_id}/select-option")
async def select_feedback_option(feedback_id: str, choice: FeedbackUserChoice, user=Depends(require_auth)):
    \"\"\"User selects solution option for Tier 2 feedback.\"\"\"
    db = get_db()
    session = db()
    try:
        # Verify ownership and status
        result = session.execute(text(\"\"\"
            SELECT user_email, status, tier FROM feedback WHERE id = :id
        \"\"\"), {"id": feedback_id}).fetchone()
        
        if not result:
            raise HTTPException(404, "Feedback nicht gefunden")
        if result[0] != user.get("sub"):
            raise HTTPException(403, "Nicht berechtigt")
        if result[1] != "waiting_user":
            raise HTTPException(400, "Feedback wartet nicht auf User-Auswahl")
        
        session.execute(text(\"\"\"
            UPDATE feedback SET 
                user_selected_option = :option,
                user_selected_at = CURRENT_TIMESTAMP,
                status = 'in_arbeit'
            WHERE id = :id
        \"\"\"), {"id": feedback_id, "option": choice.selected_option})
        session.commit()
        
        return {"message": "Option ausgewählt", "status": "in_arbeit"}
        
    finally:
        session.close()


@app.post("/api/feedback/{feedback_id}/comment")
async def add_feedback_comment(feedback_id: str, data: FeedbackCommentCreate, user=Depends(require_auth)):
    \"\"\"Add comment to feedback.\"\"\"
    db = get_db()
    session = db()
    try:
        comment_id = str(uuid.uuid4())
        
        session.execute(text(\"\"\"
            INSERT INTO feedback_comments (id, feedback_id, user_id, user_email, comment, is_internal)
            VALUES (:id, :fid, :uid, :email, :comment, :internal)
        \"\"\"), {
            "id": comment_id,
            "fid": feedback_id,
            "uid": user.get("user_id"),
            "email": user.get("sub"),
            "comment": data.comment,
            "internal": data.is_internal
        })
        session.commit()
        
        return {"id": comment_id, "message": "Kommentar hinzugefügt"}
        
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN FEEDBACK ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/admin/feedback")
async def list_all_feedback(
    status: Optional[str] = None,
    tier: Optional[int] = None,
    category: Optional[str] = None,
    priority: Optional[str] = None,
    user=Depends(require_permission("platform.admin_dashboard"))
):
    \"\"\"List all feedbacks with filters.\"\"\"
    db = get_db()
    session = db()
    try:
        query = "SELECT * FROM feedback WHERE 1=1"
        params = {}
        
        if status:
            query += " AND status = :status"
            params["status"] = status
        if tier:
            query += " AND tier = :tier"
            params["tier"] = tier
        if category:
            query += " AND category = :category"
            params["category"] = category
        if priority:
            query += " AND priority = :priority"
            params["priority"] = priority
            
        query += " ORDER BY created_at DESC LIMIT 100"
        
        result = session.execute(text(query), params)
        columns = result.keys()
        
        feedbacks = []
        for row in result:
            fb = dict(zip(columns, row))
            # Convert datetime to ISO
            for key in ["created_at", "updated_at", "approved_at", "resolved_at", "user_selected_at"]:
                if fb.get(key):
                    fb[key] = fb[key].isoformat()
            # Parse JSON fields
            for key in ["ai_solution_risks", "ai_related_feedback", "solution_options"]:
                if fb.get(key) and isinstance(fb[key], str):
                    fb[key] = json.loads(fb[key])
            feedbacks.append(fb)
        
        return feedbacks
        
    finally:
        session.close()


@app.get("/api/admin/feedback/{feedback_id}")
async def get_feedback_detail(feedback_id: str, user=Depends(require_permission("platform.admin_dashboard"))):
    \"\"\"Get detailed feedback with comments and history.\"\"\"
    db = get_db()
    session = db()
    try:
        # Get feedback
        result = session.execute(text("SELECT * FROM feedback WHERE id = :id"), {"id": feedback_id})
        row = result.fetchone()
        if not row:
            raise HTTPException(404, "Feedback nicht gefunden")
        
        columns = result.keys()
        feedback = dict(zip(columns, row))
        
        # Get comments
        comments_result = session.execute(text(\"\"\"
            SELECT id, user_email, comment, is_internal, created_at
            FROM feedback_comments 
            WHERE feedback_id = :id 
            ORDER BY created_at ASC
        \"\"\"), {"id": feedback_id})
        
        feedback["comments"] = [
            {"id": r[0], "user_email": r[1], "comment": r[2], "is_internal": r[3], "created_at": r[4].isoformat()}
            for r in comments_result
        ]
        
        # Get history
        history_result = session.execute(text(\"\"\"
            SELECT id, changed_by_email, changed_at, field_changed, old_value, new_value, action_type
            FROM feedback_history 
            WHERE feedback_id = :id 
            ORDER BY changed_at ASC
        \"\"\"), {"id": feedback_id})
        
        feedback["history"] = [
            {"id": r[0], "changed_by": r[1], "changed_at": r[2].isoformat(), "field": r[3], "old": r[4], "new": r[5], "action": r[6]}
            for r in history_result
        ]
        
        return feedback
        
    finally:
        session.close()


@app.patch("/api/admin/feedback/{feedback_id}")
async def update_feedback(feedback_id: str, data: FeedbackUpdate, user=Depends(require_permission("platform.admin_dashboard"))):
    \"\"\"Update feedback fields.\"\"\"
    db = get_db()
    session = db()
    try:
        updates = []
        params = {"id": feedback_id}
        
        for field in ["status", "priority", "category", "affected_area", "assigned_to", "resolution_note", "github_issue"]:
            value = getattr(data, field, None)
            if value is not None:
                updates.append(f"{field} = :{field}")
                params[field] = value
        
        if data.tier_override:
            updates.append("tier_override = :tier_override")
            updates.append("tier_override_by = :override_by")
            updates.append("tier_override_reason = :override_reason")
            params["tier_override"] = data.tier_override
            params["override_by"] = user.get("sub")
            params["override_reason"] = data.tier_override_reason
        
        if not updates:
            raise HTTPException(400, "Keine Änderungen")
        
        query = f"UPDATE feedback SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = :id"
        session.execute(text(query), params)
        session.commit()
        
        return {"message": "Feedback aktualisiert"}
        
    finally:
        session.close()


@app.post("/api/admin/feedback/{feedback_id}/approve")
async def approve_feedback(feedback_id: str, approval: FeedbackApproval, user=Depends(require_permission("platform.admin_dashboard"))):
    \"\"\"Approve or reject Tier 3 feedback.\"\"\"
    db = get_db()
    session = db()
    try:
        if approval.action == "approve":
            session.execute(text(\"\"\"
                UPDATE feedback SET
                    status = 'in_arbeit',
                    approved_by = :by,
                    approved_at = CURRENT_TIMESTAMP,
                    approval_note = :note
                WHERE id = :id AND status = 'waiting_admin'
            \"\"\"), {"id": feedback_id, "by": user.get("sub"), "note": approval.note})
            
        elif approval.action == "reject":
            session.execute(text(\"\"\"
                UPDATE feedback SET
                    status = 'abgelehnt',
                    rejected_reason = :reason
                WHERE id = :id
            \"\"\"), {"id": feedback_id, "reason": approval.note})
            
        session.commit()
        
        # Log action
        session.execute(text(\"\"\"
            INSERT INTO feedback_history (id, feedback_id, changed_by_email, action_type, new_value)
            VALUES (:id, :fid, :email, :action, :note)
        \"\"\"), {
            "id": str(uuid.uuid4()),
            "fid": feedback_id,
            "email": user.get("sub"),
            "action": "approval" if approval.action == "approve" else "rejection",
            "note": approval.note
        })
        session.commit()
        
        return {"message": f"Feedback {approval.action}d"}
        
    finally:
        session.close()


@app.post("/api/admin/feedback/{feedback_id}/triage")
async def retriage_feedback(feedback_id: str, user=Depends(require_permission("platform.admin_dashboard"))):
    \"\"\"Re-run AI triage on feedback.\"\"\"
    db = get_db()
    session = db()
    try:
        result = session.execute(text("SELECT message, tab_context FROM feedback WHERE id = :id"), {"id": feedback_id})
        row = result.fetchone()
        if not row:
            raise HTTPException(404, "Feedback nicht gefunden")
        
        triage = await ai_triage_feedback(row[0], row[1], ANTHROPIC_API_KEY, ANTHROPIC_MODEL_LIGHT)
        
        session.execute(text(\"\"\"
            UPDATE feedback SET
                ai_category = :cat, ai_priority = :pri, ai_summary = :sum, ai_suggested_tier = :tier,
                category = :cat, priority = :pri, tier = :tier, tier_reason = :reason,
                status = 'triaged'
            WHERE id = :id
        \"\"\"), {
            "id": feedback_id,
            "cat": triage.get("category"),
            "pri": triage.get("priority"),
            "sum": triage.get("summary"),
            "tier": triage.get("tier"),
            "reason": triage.get("tier_reason")
        })
        session.commit()
        
        return {"message": "Triage abgeschlossen", "result": triage}
        
    finally:
        session.close()


@app.post("/api/admin/feedback/{feedback_id}/github")
async def create_github_issue_from_feedback(feedback_id: str, user=Depends(require_permission("platform.admin_dashboard"))):
    \"\"\"Create GitHub issue from feedback.\"\"\"
    db = get_db()
    session = db()
    try:
        result = session.execute(text(\"\"\"
            SELECT message, ai_summary, category, priority, tier, user_email, tab_context
            FROM feedback WHERE id = :id
        \"\"\"), {"id": feedback_id})
        row = result.fetchone()
        if not row:
            raise HTTPException(404, "Feedback nicht gefunden")
        
        # Create issue
        title = row[1] or row[0][:100]
        body = f\"\"\"## User Feedback

**Von:** {row[5]}
**Tab:** {row[6] or 'Unbekannt'}
**Tier:** {row[4]}
**Kategorie:** {row[2]}
**Priorität:** {row[3]}

## Nachricht

{row[0]}

---
*Erstellt via BEATRIX Feedback System*
\"\"\"
        
        labels = [row[2] or "feedback", f"priority:{row[3] or 'medium'}"]
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://api.github.com/repos/{GH_REPO.replace('complementarity-context-framework', 'bea-lab-frontend')}/issues",
                headers={
                    "Authorization": f"token {GH_TOKEN}",
                    "Accept": "application/vnd.github.v3+json"
                },
                json={
                    "title": f"[Feedback #{feedback_id[:8]}] {title[:80]}",
                    "body": body,
                    "labels": labels
                }
            )
            
            if response.status_code == 201:
                issue_data = response.json()
                github_url = issue_data.get("html_url")
                
                session.execute(text(\"\"\"
                    UPDATE feedback SET github_issue = :url WHERE id = :id
                \"\"\"), {"id": feedback_id, "url": github_url})
                session.commit()
                
                return {"github_url": github_url, "message": "GitHub Issue erstellt"}
            else:
                raise HTTPException(500, f"GitHub API Fehler: {response.status_code}")
        
    finally:
        session.close()


@app.get("/api/admin/feedback/stats")
async def get_feedback_stats(user=Depends(require_permission("platform.admin_dashboard"))):
    \"\"\"Get feedback statistics for dashboard.\"\"\"
    db = get_db()
    session = db()
    try:
        result = session.execute(text(\"\"\"
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'neu') as neu,
                COUNT(*) FILTER (WHERE status IN ('waiting_user', 'waiting_admin', 'waiting_owner')) as waiting,
                COUNT(*) FILTER (WHERE status = 'in_arbeit') as in_arbeit,
                COUNT(*) FILTER (WHERE status = 'geloest') as geloest,
                COUNT(*) FILTER (WHERE tier = 1) as tier_1,
                COUNT(*) FILTER (WHERE tier = 2) as tier_2,
                COUNT(*) FILTER (WHERE tier = 3) as tier_3,
                COUNT(*) FILTER (WHERE tier = 4) as tier_4,
                COUNT(*) FILTER (WHERE tier = 1 AND status = 'geloest') as auto_resolved
            FROM feedback
        \"\"\"))
        row = result.fetchone()
        
        return {
            "total": row[0],
            "by_status": {
                "neu": row[1],
                "waiting": row[2],
                "in_arbeit": row[3],
                "geloest": row[4]
            },
            "by_tier": {
                "1": row[5],
                "2": row[6],
                "3": row[7],
                "4": row[8]
            },
            "auto_resolved": row[9],
            "auto_resolved_pct": round(row[9] / max(row[0], 1) * 100, 1)
        }
        
    finally:
        session.close()
"""
