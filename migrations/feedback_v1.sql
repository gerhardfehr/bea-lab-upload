-- ═══════════════════════════════════════════════════════════════════════════════
-- BEATRIX Feedback Governance System — Database Migration
-- Version: 1.0
-- Date: 2026-02-15
-- ═══════════════════════════════════════════════════════════════════════════════

-- Run this migration on the PostgreSQL database (Railway)
-- Connection: postgresql://beatrix:bea_lab_2026_secure@<host>/beatrix

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback
-- Main feedback entries with governance workflow
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback (
    id VARCHAR(50) PRIMARY KEY,
    
    -- Erfassung (Capture)
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Inhalt (Content)
    message TEXT NOT NULL,
    screenshot_url TEXT,
    tab_context VARCHAR(50),
    screen_size VARCHAR(20),
    browser_info TEXT,
    page_url TEXT,
    
    -- Klassifizierung (Classification)
    category VARCHAR(20) CHECK (category IN ('bug', 'ux', 'feature', 'question', 'other')),
    priority VARCHAR(20) CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    affected_area VARCHAR(50),
    
    -- Status & Workflow
    status VARCHAR(30) DEFAULT 'neu' CHECK (status IN (
        'neu', 'triaged', 'waiting_user', 'waiting_admin', 'waiting_owner',
        'in_arbeit', 'testing', 'geloest', 'abgelehnt'
    )),
    assigned_to VARCHAR(50),
    
    -- Governance (Tier System)
    tier INTEGER CHECK (tier BETWEEN 1 AND 4),
    tier_reason TEXT,
    tier_override INTEGER CHECK (tier_override BETWEEN 1 AND 4),
    tier_override_by VARCHAR(50),
    tier_override_reason TEXT,
    requires_approval_from VARCHAR(20) DEFAULT 'none' CHECK (requires_approval_from IN (
        'none', 'user', 'admin', 'owner'
    )),
    
    -- AI-Analyse
    ai_category VARCHAR(20),
    ai_priority VARCHAR(20),
    ai_summary TEXT,
    ai_suggested_tier INTEGER,
    ai_solution_code TEXT,
    ai_solution_preview_url TEXT,
    ai_solution_confidence FLOAT,
    ai_solution_risks JSONB,
    ai_related_feedback JSONB,
    ai_is_duplicate_of VARCHAR(50),
    
    -- Approval-Workflow
    approved_by VARCHAR(50),
    approved_at TIMESTAMP,
    approval_note TEXT,
    rejected_reason TEXT,
    
    -- User-Choice (Tier 2)
    solution_options JSONB,
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

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_email);
CREATE INDEX IF NOT EXISTS idx_feedback_tier ON feedback(tier);
CREATE INDEX IF NOT EXISTS idx_feedback_priority ON feedback(priority);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_waiting ON feedback(status) WHERE status LIKE 'waiting_%';

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback_comments
-- Comments on feedback (internal and external)
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback_comments (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    comment TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT FALSE,  -- Internal = only visible to admins
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_comments_feedback ON feedback_comments(feedback_id);
CREATE INDEX IF NOT EXISTS idx_feedback_comments_created ON feedback_comments(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback_history
-- Audit log for all changes to feedback
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback_history (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    changed_by VARCHAR(50),
    changed_by_email VARCHAR(320),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    field_changed VARCHAR(50),
    old_value TEXT,
    new_value TEXT,
    action_type VARCHAR(30) CHECK (action_type IN (
        'created', 'status_changed', 'priority_changed', 'tier_changed',
        'assigned', 'approved', 'rejected', 'resolved', 'commented', 'github_linked'
    ))
);

CREATE INDEX IF NOT EXISTS idx_feedback_history_feedback ON feedback_history(feedback_id);
CREATE INDEX IF NOT EXISTS idx_feedback_history_changed ON feedback_history(changed_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback_auto_patterns
-- Known patterns for automatic Tier 1 fixes
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback_auto_patterns (
    id VARCHAR(50) PRIMARY KEY,
    pattern_name VARCHAR(100) NOT NULL UNIQUE,
    pattern_regex TEXT,                    -- Regex to match feedback message
    pattern_keywords JSONB,                -- Keywords to match
    affected_area VARCHAR(50),
    fix_template TEXT,                     -- Code template for fix
    fix_type VARCHAR(30),                  -- css, js, content, config
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- TRIGGER: Auto-update updated_at
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION update_feedback_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS feedback_updated_at ON feedback;
CREATE TRIGGER feedback_updated_at
    BEFORE UPDATE ON feedback
    FOR EACH ROW
    EXECUTE FUNCTION update_feedback_timestamp();

-- ═══════════════════════════════════════════════════════════════════════════════
-- SEED DATA: Initial auto-fix patterns for Tier 1
-- ═══════════════════════════════════════════════════════════════════════════════

INSERT INTO feedback_auto_patterns (id, pattern_name, pattern_keywords, affected_area, fix_type)
VALUES 
    ('pat-typo', 'Typo Fix', '["typo", "tippfehler", "schreibfehler", "rechtschreibung"]', 'other', 'content'),
    ('pat-css-overflow', 'CSS Overflow', '["abgeschnitten", "text überlappt", "overflow", "truncated"]', 'other', 'css'),
    ('pat-tooltip', 'Tooltip Text', '["tooltip", "hover text", "hinweis falsch"]', 'other', 'content'),
    ('pat-icon', 'Missing Icon', '["icon fehlt", "symbol fehlt", "bild fehlt"]', 'other', 'css'),
    ('pat-loading', 'Loading Issue', '["lädt ewig", "spinner", "loading", "hängt"]', 'other', 'js'),
    ('pat-date', 'Date Format', '["datum falsch", "datumsformat", "falsches datum"]', 'other', 'js')
ON CONFLICT (pattern_name) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════════
-- VIEWS: Dashboard Statistics
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW feedback_stats AS
SELECT
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE status = 'neu') as neu,
    COUNT(*) FILTER (WHERE status = 'triaged') as triaged,
    COUNT(*) FILTER (WHERE status LIKE 'waiting_%') as waiting,
    COUNT(*) FILTER (WHERE status = 'in_arbeit') as in_arbeit,
    COUNT(*) FILTER (WHERE status = 'geloest') as geloest,
    COUNT(*) FILTER (WHERE status = 'abgelehnt') as abgelehnt,
    COUNT(*) FILTER (WHERE tier = 1) as tier_1,
    COUNT(*) FILTER (WHERE tier = 2) as tier_2,
    COUNT(*) FILTER (WHERE tier = 3) as tier_3,
    COUNT(*) FILTER (WHERE tier = 4) as tier_4,
    COUNT(*) FILTER (WHERE tier = 1 AND status = 'geloest') as auto_resolved,
    AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) 
        FILTER (WHERE resolved_at IS NOT NULL) as avg_resolution_hours
FROM feedback;

-- ═══════════════════════════════════════════════════════════════════════════════
-- GRANTS: Permissions
-- ═══════════════════════════════════════════════════════════════════════════════

-- Ensure beatrix user has access
GRANT ALL ON feedback TO beatrix;
GRANT ALL ON feedback_comments TO beatrix;
GRANT ALL ON feedback_history TO beatrix;
GRANT ALL ON feedback_auto_patterns TO beatrix;
GRANT SELECT ON feedback_stats TO beatrix;

COMMIT;

-- ═══════════════════════════════════════════════════════════════════════════════
-- VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

-- Run these to verify migration:
-- SELECT * FROM feedback_stats;
-- SELECT * FROM feedback_auto_patterns;
-- \d feedback
