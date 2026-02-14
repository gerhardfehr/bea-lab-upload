-- ═══════════════════════════════════════════════════════════════════════════════
-- BEATRIX Feedback Governance System — Database Migration
-- Version: 1.0.0
-- Date: 2026-02-15
-- ═══════════════════════════════════════════════════════════════════════════════

-- Run this migration on Railway PostgreSQL:
-- psql $DATABASE_URL < migration_feedback_v1.sql

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback
-- Main feedback storage with governance fields
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback (
    id VARCHAR(50) PRIMARY KEY,
    
    -- Erfassung (Submission)
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
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
    approved_at TIMESTAMP WITH TIME ZONE,
    approval_note TEXT,
    rejected_reason TEXT,
    
    -- User-Choice (Tier 2)
    solution_options JSONB,
    user_selected_option VARCHAR(50),
    user_selected_at TIMESTAMP WITH TIME ZONE,
    
    -- Resolution
    resolution_note TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(50),
    
    -- External Links
    github_issue VARCHAR(200),
    related_commit VARCHAR(100),
    
    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_email);
CREATE INDEX IF NOT EXISTS idx_feedback_tier ON feedback(tier);
CREATE INDEX IF NOT EXISTS idx_feedback_priority ON feedback(priority);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_approval ON feedback(requires_approval_from) WHERE requires_approval_from != 'none';

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback_comments
-- Comments and internal notes on feedbacks
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback_comments (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    user_id VARCHAR(50),
    user_email VARCHAR(320) NOT NULL,
    comment TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_comments_feedback ON feedback_comments(feedback_id);
CREATE INDEX IF NOT EXISTS idx_feedback_comments_created ON feedback_comments(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback_history
-- Audit trail for all changes
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback_history (
    id VARCHAR(50) PRIMARY KEY,
    feedback_id VARCHAR(50) NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    changed_by VARCHAR(50),
    changed_by_email VARCHAR(320),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    field_changed VARCHAR(50),
    old_value TEXT,
    new_value TEXT,
    action_type VARCHAR(30) CHECK (action_type IN (
        'created', 'status_change', 'tier_change', 'assignment', 
        'approval', 'rejection', 'comment', 'user_selection', 
        'auto_fix', 'github_link', 'resolved'
    ))
);

CREATE INDEX IF NOT EXISTS idx_feedback_history_feedback ON feedback_history(feedback_id);
CREATE INDEX IF NOT EXISTS idx_feedback_history_changed ON feedback_history(changed_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE: feedback_auto_fix_patterns
-- Known patterns for Tier 1 automatic fixes
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feedback_auto_fix_patterns (
    id VARCHAR(50) PRIMARY KEY,
    pattern_name VARCHAR(100) NOT NULL UNIQUE,
    pattern_regex TEXT,
    pattern_keywords JSONB,
    fix_template TEXT,
    affected_files JSONB,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Insert common auto-fix patterns
INSERT INTO feedback_auto_fix_patterns (id, pattern_name, pattern_keywords, fix_template, affected_files) VALUES
('pat_typo', 'typo_fix', '["typo", "tippfehler", "schreibfehler", "rechtschreibung"]', 'String replacement in UI text', '["frontend/index.html"]'),
('pat_css', 'css_visual', '["abgeschnitten", "nicht sichtbar", "überlappt", "zu klein", "zu groß"]', 'CSS property adjustment', '["frontend/styles/main.css", "frontend/styles/components.css"]'),
('pat_tooltip', 'tooltip_text', '["tooltip", "hilfetext", "hint", "beschreibung falsch"]', 'Tooltip content update', '["frontend/index.html", "frontend/js/ui/*.js"]'),
('pat_icon', 'missing_icon', '["icon fehlt", "symbol fehlt", "bild fehlt"]', 'Asset path correction', '["frontend/index.html", "frontend/assets/"]'),
('pat_loading', 'loading_state', '["lädt ewig", "spinner", "hängt", "keine reaktion"]', 'Add timeout and error state', '["frontend/js/api.js", "frontend/js/ui/*.js"]'),
('pat_date', 'date_format', '["datum falsch", "datumsformat", "zeit falsch"]', 'Locale/format adjustment', '["frontend/js/utils.js"]')
ON CONFLICT (pattern_name) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════════
-- FUNCTION: Update timestamp trigger
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
-- FUNCTION: Auto-create history entry on status change
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION log_feedback_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO feedback_history (
            id, feedback_id, field_changed, old_value, new_value, action_type
        ) VALUES (
            gen_random_uuid()::text,
            NEW.id,
            'status',
            OLD.status,
            NEW.status,
            'status_change'
        );
    END IF;
    
    IF OLD.tier IS DISTINCT FROM NEW.tier THEN
        INSERT INTO feedback_history (
            id, feedback_id, field_changed, old_value, new_value, action_type
        ) VALUES (
            gen_random_uuid()::text,
            NEW.id,
            'tier',
            OLD.tier::text,
            NEW.tier::text,
            'tier_change'
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS feedback_status_history ON feedback;
CREATE TRIGGER feedback_status_history
    AFTER UPDATE ON feedback
    FOR EACH ROW
    EXECUTE FUNCTION log_feedback_status_change();

-- ═══════════════════════════════════════════════════════════════════════════════
-- VIEW: Feedback Dashboard Stats
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW feedback_stats AS
SELECT
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE status = 'neu') as neu,
    COUNT(*) FILTER (WHERE status = 'triaged') as triaged,
    COUNT(*) FILTER (WHERE status IN ('waiting_user', 'waiting_admin', 'waiting_owner')) as waiting,
    COUNT(*) FILTER (WHERE status = 'in_arbeit') as in_arbeit,
    COUNT(*) FILTER (WHERE status = 'testing') as testing,
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
-- PERMISSIONS (für Row Level Security falls benötigt)
-- ═══════════════════════════════════════════════════════════════════════════════

-- Grant permissions to beatrix user
GRANT ALL ON feedback TO beatrix;
GRANT ALL ON feedback_comments TO beatrix;
GRANT ALL ON feedback_history TO beatrix;
GRANT ALL ON feedback_auto_fix_patterns TO beatrix;
GRANT SELECT ON feedback_stats TO beatrix;

COMMIT;

-- ═══════════════════════════════════════════════════════════════════════════════
-- VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

-- Run this to verify the migration:
-- SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'feedback%';
-- SELECT * FROM feedback_stats;
