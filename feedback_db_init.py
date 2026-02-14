"""
BEATRIX Feedback System — Database Initialization
Runs automatically on backend startup to ensure tables exist.
Add to server.py get_db() function.
"""

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

-- Feedback history/audit
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

FEEDBACK_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_email);
CREATE INDEX IF NOT EXISTS idx_feedback_tier ON feedback(tier);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_comments_feedback ON feedback_comments(feedback_id);
CREATE INDEX IF NOT EXISTS idx_feedback_history_feedback ON feedback_history(feedback_id);
"""

def init_feedback_tables(conn):
    """Initialize feedback tables. Call from get_db() in server.py"""
    try:
        with conn.cursor() as cur:
            # Create tables
            for stmt in FEEDBACK_TABLES_SQL.split(';'):
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)
            # Create indexes
            for stmt in FEEDBACK_INDEXES_SQL.split(';'):
                stmt = stmt.strip()
                if stmt:
                    try:
                        cur.execute(stmt)
                    except Exception:
                        pass  # Index might already exist
            conn.commit()
            print("✅ Feedback tables initialized")
    except Exception as e:
        print(f"⚠️ Feedback table init warning: {e}")
        conn.rollback()
