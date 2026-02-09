"""
BEA Lab - Document Upload API
Uploads are automatically pushed to GitHub: papers/evaluated/integrated/
"""
import os, uuid, json, base64, logging, hashlib, time, hmac, random
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, JSON, Boolean, text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./beatrix.db")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_FILE_SIZE = 50 * 1024 * 1024
PORT = int(os.getenv("PORT", "8000"))

# GitHub config
GH_TOKEN = os.getenv("GH_TOKEN", "")
GH_REPO = os.getenv("GH_REPO", "FehrAdvice-Partners-AG/complementarity-context-framework")
GH_UPLOAD_PATH = os.getenv("GH_UPLOAD_PATH", "papers/evaluated/integrated")

# Auth config
JWT_SECRET = os.getenv("JWT_SECRET", "bea-lab-secret-key-change-me-2026")
JWT_EXPIRY = int(os.getenv("JWT_EXPIRY", "86400"))

# Registration domain restriction (comma-separated, empty = all allowed)
# Example: "fehradvice.com,bea-lab.io" → only these domains can register
ALLOWED_EMAIL_DOMAINS = [d.strip().lower() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()]

# Auto-admin emails (comma-separated)
# Example: "gerhard.fehr@fehradvice.com" → these users get admin on registration
ADMIN_EMAILS = [e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()]

# Email verification via Resend API (resend.com)
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "true").lower() in ("true", "1", "yes")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "BEATRIX Lab <noreply@bea-lab.io>")
APP_URL = os.getenv("APP_URL", "https://www.bea-lab.io")
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GH_CONTEXT_REPO = os.getenv("GH_CONTEXT_REPO", "FehrAdvice-Partners-AG/complementarity-context-framework")
VOYAGE_API_KEY = os.getenv("VOYAGE_API_KEY", "")
VOYAGE_MODEL = "voyage-3-lite"  # 512 dimensions, fast, free tier 200M tokens/month

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bea-lab")

def hash_password(password, salt=None):
    if salt is None:
        salt = base64.b64encode(os.urandom(16)).decode()
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return base64.b64encode(hashed).decode(), salt

def verify_password(password, stored_hash, salt):
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, stored_hash)

def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _b64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_jwt(payload):
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_enc = _b64url_encode(json.dumps(payload).encode())
    sig_input = f"{header}.{payload_enc}".encode()
    sig = _b64url_encode(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest())
    return f"{header}.{payload_enc}.{sig}"

def verify_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = _b64url_encode(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest())
        if not hmac.compare_digest(parts[2], expected_sig): return None
        payload = json.loads(_b64url_decode(parts[1]))
        if payload.get("exp", 0) < time.time(): return None
        return payload
    except: return None

async def require_auth(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    if not token: token = request.cookies.get("bea_token", "")
    payload = verify_jwt(token)
    if not payload: raise HTTPException(401, "Nicht autorisiert")
    return payload

def _user_crm_payload(user):
    """Compute CRM access for JWT. Rules:
    - Only @fehradvice.com emails eligible
    - Senior Management / Partner / Admin: CRM auto-enabled
    - lead_management: see own leads (viewer + owner_code)
    - Others need explicit crm_access=True in DB
    """
    email = (user.email or "").lower()
    is_fa = email.endswith("@fehradvice.com")
    role = (user.role or "researcher").lower()
    senior_roles = ("senior_management", "partner")
    auto_crm = role in senior_roles or user.is_admin
    effective_crm = user.crm_access or (auto_crm and is_fa)
    effective_lead_mgmt = getattr(user, 'lead_management', False) or auto_crm
    return {
        "crm_access": effective_crm and is_fa,
        "crm_role": user.crm_role or ("admin" if user.is_admin else ("manager" if role in senior_roles else "none")),
        "crm_owner_code": user.crm_owner_code or "",
        "lead_management": bool(effective_lead_mgmt and effective_crm and is_fa),
    }

Base = declarative_base()
_engine = None
_SessionLocal = None

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(320), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=True)
    password_hash = Column(String(500), nullable=False)
    password_salt = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    email_verified = Column(Boolean, default=False)
    verification_token = Column(String(200), nullable=True)
    verification_sent_at = Column(DateTime, nullable=True)
    reset_token = Column(String(200), nullable=True)
    reset_sent_at = Column(DateTime, nullable=True)
    # Profile fields
    position = Column(String(200), nullable=True)
    company = Column(String(200), nullable=True)
    bio = Column(Text, nullable=True)
    phone = Column(String(50), nullable=True)
    linkedin_url = Column(String(500), nullable=True)
    linkedin_id = Column(String(100), nullable=True)
    profile_photo_url = Column(String(1000), nullable=True)
    expertise = Column(JSON, nullable=True)  # ["Behavioral Economics", "Strategy", ...]
    role = Column(String(50), default="researcher")  # researcher, sales, operations
    crm_access = Column(Boolean, default=False)  # explicitly enabled for CRM
    crm_role = Column(String(30), default="none")  # none, viewer, manager, admin
    crm_owner_code = Column(String(20), nullable=True)  # OWN-GF, OWN-EB, etc.
    lead_management = Column(Boolean, default=False)  # access to lead management suite
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class UserInsight(Base):
    __tablename__ = "user_insights"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email = Column(String(320), nullable=False, index=True)
    # Question & Answer
    question_text = Column(Text, nullable=False)
    question_category = Column(String(50), nullable=True)  # onboarding, login, voluntary
    answer_text = Column(Text, nullable=True)
    choice_index = Column(Integer, nullable=True)  # 1,2,3,4(custom),5(beatrix)
    # Behavioral Metadata
    latency_ms = Column(Integer, nullable=True)  # Time from question shown to answer
    session_number = Column(Integer, default=1)  # nth login/session
    question_number = Column(Integer, default=1)  # nth question in this session (1=mandatory, 2-3=nudged, 4+=voluntary)
    was_mandatory = Column(Boolean, default=True)
    was_nudged = Column(Boolean, default=False)
    skipped = Column(Boolean, default=False)
    # Extracted Insights
    domain_signal = Column(String(20), nullable=True)  # REL/FIN/HLT/ENV/POL/ORG/EDU/OTH
    thinking_style = Column(String(30), nullable=True)  # theoretical/practical/analytical/creative
    abstraction_level = Column(String(20), nullable=True)  # abstract/concrete/mixed
    autonomy_signal = Column(String(20), nullable=True)  # high(option4)/low(option5)/moderate(1-3)
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    context = Column(String(20), default="login")  # onboarding, login, model_building

class Document(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=True)
    source_type = Column(String(20), nullable=False)
    file_type = Column(String(10), nullable=True)
    file_path = Column(String(1000), nullable=True)
    file_size = Column(Integer, nullable=True)
    database_target = Column(String(50), nullable=False, default="knowledge_base")
    category = Column(String(50), nullable=True)
    language = Column(String(10), nullable=True)
    tags = Column(JSON, nullable=True)
    doc_metadata = Column("metadata", JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(20), default="indexed")
    github_url = Column(String(1000), nullable=True)
    uploaded_by = Column(String(320), nullable=True)
    content_hash = Column(String(64), nullable=True, index=True)

def get_db():
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_engine(DATABASE_URL, pool_pre_ping=True)
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
        try:
            Base.metadata.create_all(bind=_engine)
            try:
                from sqlalchemy import text
                with _engine.connect() as conn:
                    conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS github_url VARCHAR(1000)"))
                    conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS uploaded_by VARCHAR(320)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token VARCHAR(200)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_sent_at TIMESTAMP"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(200)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_sent_at TIMESTAMP"))
                    conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64)"))
                    # Profile fields
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS position VARCHAR(200)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS company VARCHAR(200)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS linkedin_url VARCHAR(500)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS linkedin_id VARCHAR(100)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_photo_url VARCHAR(1000)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS expertise JSON"))
                    # Chat messages table
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS chat_messages (
                        id VARCHAR PRIMARY KEY, user_email VARCHAR(320) NOT NULL,
                        role VARCHAR(20) NOT NULL, content TEXT NOT NULL,
                        sources JSON, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    # User insights / behavioral profiling table
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS user_insights (
                        id VARCHAR PRIMARY KEY, user_email VARCHAR(320) NOT NULL,
                        question_text TEXT NOT NULL, question_category VARCHAR(50),
                        answer_text TEXT, choice_index INTEGER,
                        latency_ms INTEGER, session_number INTEGER DEFAULT 1,
                        question_number INTEGER DEFAULT 1, was_mandatory BOOLEAN DEFAULT TRUE,
                        was_nudged BOOLEAN DEFAULT FALSE, skipped BOOLEAN DEFAULT FALSE,
                        domain_signal VARCHAR(20), thinking_style VARCHAR(30),
                        abstraction_level VARCHAR(20), autonomy_signal VARCHAR(20),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        context VARCHAR(20) DEFAULT 'login')"""))
                    # pgvector for semantic search (AlphaGo-style)
                    try:
                        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                        conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS embedding vector(512)"))
                        conn.commit()
                        logger.info("pgvector enabled with embedding column")
                    except Exception as ve:
                        logger.warning(f"pgvector not available: {ve}")
                        conn.rollback()
                        # Fallback: use TEXT column to store embeddings as JSON
                        try:
                            conn.execute(text("ALTER TABLE documents ADD COLUMN IF NOT EXISTS embedding_json TEXT"))
                            conn.commit()
                            logger.info("Using JSON embedding fallback (no pgvector)")
                        except:
                            conn.rollback()
                    # Auto-verify existing admin users
                    conn.execute(text("UPDATE users SET email_verified = TRUE WHERE is_admin = TRUE AND email_verified = FALSE"))
                    # Role field for tab visibility
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'researcher'"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS crm_access BOOLEAN DEFAULT FALSE"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS crm_role VARCHAR(30) DEFAULT 'none'"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS crm_owner_code VARCHAR(20)"))
                    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS lead_management BOOLEAN DEFAULT FALSE"))
                    # Auto-enable CRM for FehrAdvice admins (Senior Management) – runs every startup
                    conn.execute(text("""UPDATE users SET crm_access = TRUE, crm_role = 'admin' 
                        WHERE is_admin = TRUE AND email LIKE '%%@fehradvice.com'"""))
                    # Also enable for known senior management
                    conn.execute(text("""UPDATE users SET crm_access = TRUE, crm_role = 'admin', crm_owner_code = 'OWN-GF'
                        WHERE email = 'gerhard.fehr@fehradvice.com'"""))
                    # Ensure known admins have is_admin flag
                    conn.execute(text("""UPDATE users SET is_admin = TRUE WHERE email IN ('gerhard.fehr@fehradvice.com', 'nora.gavazajsusuri@fehradvice.com') AND is_admin = FALSE"""))
                    # Set initial roles for sales users
                    conn.execute(text("UPDATE users SET role = 'sales' WHERE email IN ('nora.gavazajsusuri@fehradvice.com', 'maria.neumann@fehradvice.com') AND (role IS NULL OR role = 'researcher')"))
                    # Leads table
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS leads (
                        id VARCHAR PRIMARY KEY, company VARCHAR(500),
                        contact VARCHAR(200), email VARCHAR(320),
                        stage VARCHAR(50) DEFAULT 'kontakt',
                        value REAL DEFAULT 0, source VARCHAR(200),
                        notes TEXT, created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    # ── CRM Tables ──
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS crm_companies (
                        id VARCHAR PRIMARY KEY,
                        name VARCHAR(500) NOT NULL,
                        domain VARCHAR(200),
                        industry VARCHAR(200),
                        size VARCHAR(50),
                        website VARCHAR(500),
                        address TEXT,
                        notes TEXT,
                        created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS crm_contacts (
                        id VARCHAR PRIMARY KEY,
                        company_id VARCHAR REFERENCES crm_companies(id),
                        name VARCHAR(300) NOT NULL,
                        email VARCHAR(320),
                        phone VARCHAR(50),
                        position VARCHAR(200),
                        role_type VARCHAR(50) DEFAULT 'kontakt',
                        psi_profile JSON,
                        notes TEXT,
                        created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS crm_deals (
                        id VARCHAR PRIMARY KEY,
                        company_id VARCHAR REFERENCES crm_companies(id),
                        contact_id VARCHAR REFERENCES crm_contacts(id),
                        title VARCHAR(500) NOT NULL,
                        stage VARCHAR(50) DEFAULT 'erstkontakt',
                        value REAL DEFAULT 0,
                        probability INTEGER DEFAULT 10,
                        source VARCHAR(200),
                        next_action VARCHAR(500),
                        next_action_date DATE,
                        owner VARCHAR(320),
                        context_id VARCHAR,
                        notes TEXT,
                        closed_at TIMESTAMP,
                        lost_reason TEXT,
                        created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS crm_activities (
                        id VARCHAR PRIMARY KEY,
                        deal_id VARCHAR REFERENCES crm_deals(id),
                        company_id VARCHAR REFERENCES crm_companies(id),
                        contact_id VARCHAR REFERENCES crm_contacts(id),
                        type VARCHAR(30) NOT NULL,
                        subject VARCHAR(500),
                        description TEXT,
                        due_date TIMESTAMP,
                        done BOOLEAN DEFAULT FALSE,
                        created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    # Contexts / Ausgangslage table
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS contexts (
                        id VARCHAR PRIMARY KEY, client VARCHAR(500),
                        project VARCHAR(500), domain VARCHAR(20),
                        status VARCHAR(50) DEFAULT 'aktiv',
                        situation TEXT, goal TEXT, constraints TEXT,
                        created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    # Feedback table
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS feedback (
                        id VARCHAR PRIMARY KEY,
                        type VARCHAR(20) DEFAULT 'bug',
                        comment TEXT,
                        screenshot TEXT,
                        page VARCHAR(100),
                        url VARCHAR(1000),
                        viewport VARCHAR(50),
                        user_agent VARCHAR(500),
                        status VARCHAR(20) DEFAULT 'neu',
                        created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
                    conn.commit()
            except: pass
            logger.info(f"DB connected: {DATABASE_URL[:50]}...")
        except Exception as e:
            logger.error(f"DB init error: {e}")
            _engine = None; _SessionLocal = None
            raise HTTPException(503, "Datenbank nicht bereit")
    return _SessionLocal()

def push_to_github(filename, content_bytes):
    if not GH_TOKEN:
        logger.warning("GH_TOKEN not set, skipping GitHub push")
        return {"error": "GH_TOKEN not configured"}
    import urllib.request, ssl

# ========== VECTOR EMBEDDING (AlphaGo Neural Network) ==========

def embed_texts(texts: list, input_type: str = "document") -> list:
    """Generate embeddings via Voyage AI. Returns list of 512-dim vectors."""
    if not VOYAGE_API_KEY or not texts:
        return []
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    # Truncate long texts (Voyage limit ~32k tokens)
    truncated = [t[:16000] for t in texts]
    payload = json.dumps({
        "input": truncated,
        "model": VOYAGE_MODEL,
        "input_type": input_type  # "document" for storage, "query" for search
    }).encode()
    req = urllib.request.Request("https://api.voyageai.com/v1/embeddings", data=payload, method="POST",
        headers={"Authorization": f"Bearer {VOYAGE_API_KEY}", "Content-Type": "application/json"})
    try:
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        return [d["embedding"] for d in resp.get("data", [])]
    except Exception as e:
        logger.error(f"Voyage AI embedding error: {e}")
        return []

def embed_single(text: str, input_type: str = "document") -> list:
    """Embed a single text. Returns 512-dim vector or empty list."""
    results = embed_texts([text], input_type)
    return results[0] if results else []

def embed_document(db, doc_id: str):
    """Generate and store embedding for a single document."""
    if not VOYAGE_API_KEY: return False
    from sqlalchemy import text as sql_text
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc or not doc.content: return False
    embed_input = f"{doc.title or ''}\n{doc.content[:15000]}"
    vec = embed_single(embed_input, "document")
    if not vec: return False
    try:
        # Try pgvector first
        vec_str = f"[{','.join(str(v) for v in vec)}]"
        db.execute(sql_text("UPDATE documents SET embedding = :vec WHERE id = :id"), {"vec": vec_str, "id": doc_id})
        db.commit()
        logger.info(f"Embedded doc (pgvector): {doc.title[:50]}")
        return True
    except Exception:
        db.rollback()
        try:
            # Fallback: store as JSON text
            vec_json = json.dumps(vec)
            db.execute(sql_text("UPDATE documents SET embedding_json = :vec WHERE id = :id"), {"vec": vec_json, "id": doc_id})
            db.commit()
            logger.info(f"Embedded doc (JSON): {doc.title[:50]}")
            return True
        except Exception as e:
            logger.error(f"Store embedding error: {e}")
            db.rollback()
            return False

def embed_all_documents(db):
    """Embed all documents that don't have embeddings yet."""
    if not VOYAGE_API_KEY:
        logger.info("No VOYAGE_API_KEY, skipping embeddings")
        return 0
    from sqlalchemy import text as sql_text
    # Find docs without embeddings - try pgvector column first, then JSON
    try:
        result = db.execute(sql_text("SELECT id, title, content FROM documents WHERE embedding IS NULL AND content IS NOT NULL"))
        rows = result.fetchall()
        use_pgvector = True
    except Exception:
        db.rollback()
        try:
            result = db.execute(sql_text("SELECT id, title, content FROM documents WHERE (embedding_json IS NULL OR embedding_json = '') AND content IS NOT NULL"))
            rows = result.fetchall()
            use_pgvector = False
        except Exception as e:
            db.rollback()
            logger.warning(f"Cannot query embeddings: {e}")
            return 0
    if not rows:
        logger.info("All documents already embedded")
        return 0
    logger.info(f"Embedding {len(rows)} documents (pgvector={use_pgvector})...")
    count = 0
    batch_size = 8
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i+batch_size]
        texts = [f"{r[1] or ''}\n{(r[2] or '')[:15000]}" for r in batch]
        vectors = embed_texts(texts, "document")
        for j, vec in enumerate(vectors):
            if vec:
                try:
                    if use_pgvector:
                        vec_str = f"[{','.join(str(v) for v in vec)}]"
                        db.execute(sql_text("UPDATE documents SET embedding = :vec WHERE id = :id"), {"vec": vec_str, "id": batch[j][0]})
                    else:
                        db.execute(sql_text("UPDATE documents SET embedding_json = :vec WHERE id = :id"), {"vec": json.dumps(vec), "id": batch[j][0]})
                    count += 1
                except: pass
        db.commit()
    logger.info(f"Embedded {count}/{len(rows)} documents")
    return count

def vector_search(db, query: str, limit: int = 8) -> list:
    """Semantic search. Tries pgvector, falls back to JSON + Python cosine similarity."""
    if not VOYAGE_API_KEY: return []
    from sqlalchemy import text as sql_text
    query_vec = embed_single(query, "query")
    if not query_vec: return []
    # Try pgvector first
    try:
        vec_str = f"[{','.join(str(v) for v in query_vec)}]"
        result = db.execute(sql_text("""
            SELECT id, 1 - (embedding <=> :vec::vector) as similarity
            FROM documents WHERE embedding IS NOT NULL AND content IS NOT NULL
            ORDER BY embedding <=> :vec::vector LIMIT :lim
        """), {"vec": vec_str, "lim": limit})
        rows = result.fetchall()
        scored = []
        for row in rows:
            doc = db.query(Document).filter(Document.id == row[0]).first()
            if doc: scored.append((float(row[1]) * 100, doc))
        if scored:
            logger.info(f"Vector search (pgvector): {len(scored)} results")
            return scored
    except Exception:
        db.rollback()
    # Fallback: JSON embeddings + Python cosine similarity
    try:
        result = db.execute(sql_text("SELECT id, embedding_json FROM documents WHERE embedding_json IS NOT NULL AND embedding_json != '' AND content IS NOT NULL"))
        rows = result.fetchall()
        if not rows: return []
        import math
        def cosine_sim(a, b):
            dot = sum(x*y for x,y in zip(a,b))
            na = math.sqrt(sum(x*x for x in a))
            nb = math.sqrt(sum(x*x for x in b))
            return dot / (na * nb) if na and nb else 0
        scored = []
        for row in rows:
            try:
                doc_vec = json.loads(row[1])
                sim = cosine_sim(query_vec, doc_vec)
                doc = db.query(Document).filter(Document.id == row[0]).first()
                if doc and sim > 0.3:
                    scored.append((sim * 100, doc))
            except: continue
        scored.sort(key=lambda x: -x[0])
        logger.info(f"Vector search (JSON cosine): {len(scored)} results")
        return scored[:limit]
    except Exception as e:
        logger.warning(f"Vector search error: {e}")
        return []

def fulltext_search(db, query: str, limit: int = 8) -> list:
    """PostgreSQL full-text search with ts_rank. Much better than keyword matching."""
    from sqlalchemy import text as sql_text
    try:
        # Use plainto_tsquery for natural language queries (handles German + English)
        result = db.execute(sql_text("""
            SELECT id, 
                   ts_rank_cd(
                       setweight(to_tsvector('simple', COALESCE(title, '')), 'A') ||
                       setweight(to_tsvector('simple', COALESCE(category, '')), 'B') ||
                       setweight(to_tsvector('simple', COALESCE(content, '')), 'C'),
                       plainto_tsquery('simple', :query)
                   ) as rank
            FROM documents
            WHERE content IS NOT NULL
              AND (
                  to_tsvector('simple', COALESCE(title, '')) ||
                  to_tsvector('simple', COALESCE(content, ''))
              ) @@ plainto_tsquery('simple', :query)
            ORDER BY rank DESC
            LIMIT :lim
        """), {"query": query, "lim": limit})
        rows = result.fetchall()
        scored = []
        for row in rows:
            doc = db.query(Document).filter(Document.id == row[0]).first()
            if doc:
                # Scale rank to 0-100 range, boost EBF answers
                score = float(row[1]) * 1000
                if doc.source_type == "ebf_answer":
                    score *= 3
                scored.append((score, doc))
        logger.info(f"Fulltext search for '{query[:30]}': {len(scored)} results")
        return scored
    except Exception as e:
        logger.warning(f"Fulltext search error: {e}")
        return []

# ========== END VECTOR EMBEDDING ==========
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    path = f"{GH_UPLOAD_PATH}/{filename}"
    url = f"https://api.github.com/repos/{GH_REPO}/contents/{path}"
    sha = None
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"})
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        sha = resp.get("sha")
    except: pass
    payload = {"message": f"Upload via BEA Lab: {filename}", "content": base64.b64encode(content_bytes).decode(), "branch": "main"}
    if sha: payload["sha"] = sha
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="PUT", headers={"Authorization": f"token {GH_TOKEN}", "Content-Type": "application/json", "Accept": "application/vnd.github.v3+json"})
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        logger.info(f"GitHub push OK: {path}")
        return {"url": resp.get("content", {}).get("html_url", ""), "sha": resp.get("content", {}).get("sha", ""), "path": path}
    except Exception as e:
        logger.error(f"GitHub push failed: {e}")
        return {"error": str(e)}

app = FastAPI(title="BEA Lab Upload API", version="3.7.0")

def send_verification_email(email, name, token):
    """Send verification email via Resend API"""
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set, skipping verification email")
        return False
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    verify_url = f"{APP_URL}/api/verify/{token}"
    html = f"""<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:40px 24px">
    <div style="text-align:center;margin-bottom:32px">
        <h1 style="font-size:24px;font-weight:800;color:#0a1628;margin:0">BEATRIX <span style="color:#5b8af5">Lab</span></h1>
        <p style="color:#666;font-size:14px;margin:8px 0 0">Strategic Intelligence Suite</p>
    </div>
    <p style="font-size:15px;color:#333">Hallo {name or 'dort'},</p>
    <p style="font-size:15px;color:#333;line-height:1.6">Bitte bestätige deine E-Mail-Adresse, um dein BEATRIX Lab Konto zu aktivieren:</p>
    <div style="text-align:center;margin:32px 0">
        <a href="{verify_url}" style="display:inline-block;padding:14px 36px;background:#5b8af5;color:white;text-decoration:none;border-radius:10px;font-weight:700;font-size:15px">E-Mail bestätigen</a>
    </div>
    <p style="font-size:12px;color:#999;line-height:1.5">Falls der Button nicht funktioniert, kopiere diesen Link:<br>
    <a href="{verify_url}" style="color:#5b8af5;word-break:break-all">{verify_url}</a></p>
    <p style="font-size:12px;color:#999;margin-top:24px">Dieser Link ist 24 Stunden gültig.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:32px 0">
    <p style="font-size:11px;color:#aaa;text-align:center">FehrAdvice &amp; Partners AG · Zürich</p>
</div>"""
    payload = json.dumps({
        "from": EMAIL_FROM,
        "to": [email],
        "subject": "BEATRIX Lab – E-Mail bestätigen",
        "html": html,
        "text": f"Hallo {name},\n\nBitte bestätige deine E-Mail: {verify_url}\n\nDieser Link ist 24 Stunden gültig."
    }).encode()
    try:
        req = urllib.request.Request("https://api.resend.com/emails", data=payload, method="POST",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json", "User-Agent": "BEATRIXLab/3.4"})
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        logger.info(f"Verification email sent to {email} via Resend: {resp.get('id','?')}")
        return True
    except Exception as e:
        logger.error(f"Failed to send verification email to {email}: {e}")
        return False
app.add_middleware(CORSMiddleware, allow_origins=["https://bea-lab.io", "https://www.bea-lab.io", "https://bea-lab-frontend.vercel.app", "http://localhost:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
FRONTEND_DIR = Path(__file__).parent / "frontend"

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ResetPasswordRequest(BaseModel):
    email: str

class ResetPasswordConfirm(BaseModel):
    token: str
    new_password: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    position: Optional[str] = None
    company: Optional[str] = None
    bio: Optional[str] = None
    phone: Optional[str] = None
    linkedin_url: Optional[str] = None
    expertise: Optional[List[str]] = None

class TextUploadRequest(BaseModel):
    title: str = "Untitled"
    content: str
    category: Optional[str] = "general"
    language: Optional[str] = "de"
    tags: Optional[List[str]] = []
    database: Optional[str] = "knowledge_base"

class DocumentResponse(BaseModel):
    id: str; title: str; source_type: str; file_type: Optional[str] = None
    database_target: str; status: str; created_at: str; github_url: Optional[str] = None

def extract_text(file_path, file_type):
    try:
        if file_type == "pdf":
            import fitz; doc = fitz.open(file_path); text = "\n".join(page.get_text() for page in doc); doc.close(); return text.strip()
        elif file_type == "docx":
            from docx import Document as DocxDoc; doc = DocxDoc(file_path); return "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        elif file_type in ("txt", "md", "csv", "json"):
            with open(file_path, "r", encoding="utf-8") as f: return f.read()
    except Exception as e: return f"[Extraction error: {e}]"
    return ""

@app.get("/")
async def root():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        r = FileResponse(str(index_path))
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        r.headers["Pragma"] = "no-cache"
        r.headers["Expires"] = "0"
        return r
    return {"message": "BEA Lab Upload API", "docs": "/docs"}

@app.get("/static/{filepath:path}")
async def static_files(filepath):
    file_path = FRONTEND_DIR / filepath
    if file_path.exists() and file_path.is_file(): return FileResponse(str(file_path))
    raise HTTPException(404, "Not found")

@app.post("/api/register")
async def register(request: RegisterRequest):
    email = request.email.strip().lower()
    if not email or '@' not in email: raise HTTPException(400, "Ungültige E-Mail-Adresse")
    if len(request.password) < 6: raise HTTPException(400, "Passwort muss mindestens 6 Zeichen haben")
    if ALLOWED_EMAIL_DOMAINS:
        domain = email.split('@')[-1]
        if domain not in ALLOWED_EMAIL_DOMAINS:
            allowed = ", ".join(f"@{d}" for d in ALLOWED_EMAIL_DOMAINS)
            raise HTTPException(403, f"Registrierung nur mit folgenden E-Mail-Domains erlaubt: {allowed}")
    db = get_db()
    try:
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(409, "E-Mail bereits registriert")
        pw_hash, pw_salt = hash_password(request.password)
        is_admin = email in ADMIN_EMAILS
        verification_token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        skip_verification = is_admin or not REQUIRE_EMAIL_VERIFICATION or not RESEND_API_KEY
        user = User(
            email=email, name=request.name or email.split('@')[0],
            password_hash=pw_hash, password_salt=pw_salt, is_admin=is_admin,
            email_verified=skip_verification,
            verification_token=None if skip_verification else verification_token,
            verification_sent_at=None if skip_verification else datetime.utcnow()
        )
        db.add(user); db.commit(); db.refresh(user)
        if not skip_verification:
            sent = send_verification_email(email, user.name, verification_token)
            if not sent:
                # Fallback: auto-verify if SMTP fails
                user.email_verified = True; user.verification_token = None; db.commit()
                logger.warning(f"SMTP failed, auto-verified {email}")
            else:
                logger.info(f"Verification email sent to {email}")
                return JSONResponse({"status": "verification_required", "message": "Registrierung erfolgreich! Bitte prüfe dein E-Mail-Postfach und bestätige deine E-Mail-Adresse."})
        # Admin or no verification required → direct login
        token = create_jwt({**{"sub": user.email, "name": user.name, "uid": user.id, "admin": user.is_admin, "role": user.role or "researcher", "iat": int(time.time()), "exp": int(time.time()) + JWT_EXPIRY}, **_user_crm_payload(user)})
        logger.info(f"New user: {email} (verified={user.email_verified})")
        resp = JSONResponse({"token": token, "expires_in": JWT_EXPIRY, "user": {"email": user.email, "name": user.name}})
        resp.set_cookie(key="bea_token", value=token, max_age=JWT_EXPIRY, httponly=True, samesite="lax")
        return resp
    except HTTPException: raise
    except Exception as e: db.rollback(); raise HTTPException(500, f"Fehler: {e}")
    finally: db.close()

@app.post("/api/login")
async def login(request: LoginRequest):
    email = request.email.strip().lower()
    db = get_db()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(request.password, user.password_hash, user.password_salt):
            raise HTTPException(401, "E-Mail oder Passwort falsch")
        if not user.is_active: raise HTTPException(403, "Konto deaktiviert")
        if REQUIRE_EMAIL_VERIFICATION and not user.email_verified:
            raise HTTPException(403, "E-Mail noch nicht bestätigt. Bitte prüfe dein Postfach.")
        user.last_login = datetime.utcnow(); db.commit()
        token = create_jwt({**{"sub": user.email, "name": user.name, "uid": user.id, "admin": user.is_admin, "role": user.role or "researcher", "iat": int(time.time()), "exp": int(time.time()) + JWT_EXPIRY}, **_user_crm_payload(user)})
        logger.info(f"Login: {email}")
        resp = JSONResponse({"token": token, "expires_in": JWT_EXPIRY, "user": {"email": user.email, "name": user.name}})
        resp.set_cookie(key="bea_token", value=token, max_age=JWT_EXPIRY, httponly=True, samesite="lax")
        return resp
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, f"Login-Fehler: {e}")
    finally: db.close()

@app.get("/api/verify/{token}")
async def verify_email(token: str):
    db = get_db()
    try:
        user = db.query(User).filter(User.verification_token == token).first()
        if not user:
            html = _verify_page("Ungültiger Link", "Dieser Bestätigungslink ist ungültig oder wurde bereits verwendet.", False)
            return HTMLResponse(html)
        # Check 24h expiry
        if user.verification_sent_at and (datetime.utcnow() - user.verification_sent_at).total_seconds() > 86400:
            html = _verify_page("Link abgelaufen", "Dieser Bestätigungslink ist abgelaufen. Bitte melde dich an und fordere einen neuen Link an.", False)
            return HTMLResponse(html)
        user.email_verified = True
        user.verification_token = None
        db.commit()
        logger.info(f"Email verified: {user.email}")
        html = _verify_page("E-Mail bestätigt!", f"Deine E-Mail-Adresse ({user.email}) wurde erfolgreich bestätigt. Du kannst dich jetzt anmelden.", True)
        return HTMLResponse(html)
    except Exception as e:
        logger.error(f"Verify error: {e}")
        html = _verify_page("Fehler", "Ein Fehler ist aufgetreten. Bitte versuche es erneut.", False)
        return HTMLResponse(html)
    finally: db.close()

@app.post("/api/resend-verification")
async def resend_verification(request: LoginRequest):
    email = request.email.strip().lower()
    db = get_db()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user: raise HTTPException(404, "E-Mail nicht gefunden")
        if not verify_password(request.password, user.password_hash, user.password_salt):
            raise HTTPException(401, "E-Mail oder Passwort falsch")
        if user.email_verified: raise HTTPException(400, "E-Mail bereits bestätigt")
        # Rate limit: max once every 2 minutes
        if user.verification_sent_at and (datetime.utcnow() - user.verification_sent_at).total_seconds() < 120:
            raise HTTPException(429, "Bitte warte 2 Minuten, bevor du einen neuen Link anforderst.")
        new_token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        user.verification_token = new_token
        user.verification_sent_at = datetime.utcnow()
        db.commit()
        sent = send_verification_email(email, user.name, new_token)
        if not sent: raise HTTPException(500, "E-Mail konnte nicht gesendet werden")
        return {"message": "Neuer Bestätigungslink wurde gesendet."}
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, f"Fehler: {e}")
    finally: db.close()

@app.put("/api/admin/users/{user_id}/verify")
async def admin_verify_user(user_id: str, user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        target = db.query(User).filter(User.id == user_id).first()
        if not target: raise HTTPException(404, "Benutzer nicht gefunden")
        target.email_verified = True; target.verification_token = None; db.commit()
        return {"email": target.email, "email_verified": True}
    finally: db.close()

@app.post("/api/change-password")
async def change_password(request: ChangePasswordRequest, user=Depends(require_auth)):
    db = get_db()
    try:
        db_user = db.query(User).filter(User.email == user["sub"]).first()
        if not db_user: raise HTTPException(404, "Benutzer nicht gefunden")
        if not verify_password(request.current_password, db_user.password_hash, db_user.password_salt):
            raise HTTPException(401, "Aktuelles Passwort ist falsch")
        if len(request.new_password) < 6:
            raise HTTPException(400, "Neues Passwort muss mindestens 6 Zeichen haben")
        pw_hash, pw_salt = hash_password(request.new_password)
        db_user.password_hash = pw_hash; db_user.password_salt = pw_salt; db.commit()
        logger.info(f"Password changed: {user['sub']}")
        return {"message": "Passwort erfolgreich geändert"}
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, f"Fehler: {e}")
    finally: db.close()

# ── Profile ──────────────────────────────────────────────────────────────
@app.get("/api/profile")
async def get_profile(user=Depends(require_auth)):
    db = get_db()
    try:
        u = db.query(User).filter(User.email == user["sub"]).first()
        if not u: raise HTTPException(404, "Benutzer nicht gefunden")
        return {
            "email": u.email, "name": u.name, "position": u.position, "company": u.company,
            "bio": u.bio, "phone": u.phone, "linkedin_url": u.linkedin_url,
            "linkedin_connected": bool(u.linkedin_id), "profile_photo_url": u.profile_photo_url,
            "expertise": u.expertise or [], "is_admin": u.is_admin, "role": u.role or "researcher",
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login": u.last_login.isoformat() if u.last_login else None
        }
    finally: db.close()

@app.put("/api/profile")
async def update_profile(request: ProfileUpdate, user=Depends(require_auth)):
    db = get_db()
    try:
        u = db.query(User).filter(User.email == user["sub"]).first()
        if not u: raise HTTPException(404, "Benutzer nicht gefunden")
        if request.name is not None: u.name = request.name.strip()[:200]
        if request.position is not None: u.position = request.position.strip()[:200]
        if request.company is not None: u.company = request.company.strip()[:200]
        if request.bio is not None: u.bio = request.bio.strip()[:2000]
        if request.phone is not None: u.phone = request.phone.strip()[:50]
        if request.linkedin_url is not None:
            url = request.linkedin_url.strip()
            if url and not url.startswith("http"): url = "https://" + url
            u.linkedin_url = url[:500] if url else None
        if request.expertise is not None: u.expertise = request.expertise[:20]
        db.commit()
        logger.info(f"Profile updated: {user['sub']}")
        return {"message": "Profil aktualisiert"}
    except HTTPException: raise
    except Exception as e: db.rollback(); raise HTTPException(500, f"Fehler: {e}")
    finally: db.close()

@app.post("/api/profile/photo")
async def upload_profile_photo(file: UploadFile = File(...), user=Depends(require_auth)):
    ext = file.filename.split(".")[-1].lower() if file.filename else ""
    if ext not in {"jpg", "jpeg", "png", "webp"}: raise HTTPException(400, "Nur JPG, PNG oder WebP erlaubt")
    content = await file.read()
    if len(content) > 5_000_000: raise HTTPException(400, "Max 5 MB")
    photo_id = str(uuid.uuid4())
    photo_path = UPLOAD_DIR / f"photos/{photo_id}.{ext}"
    photo_path.parent.mkdir(parents=True, exist_ok=True)
    with open(photo_path, "wb") as f: f.write(content)
    db = get_db()
    try:
        u = db.query(User).filter(User.email == user["sub"]).first()
        if not u: raise HTTPException(404)
        u.profile_photo_url = f"/api/photos/{photo_id}.{ext}"
        db.commit()
        return {"photo_url": u.profile_photo_url}
    finally: db.close()

@app.get("/api/photos/{filename}")
async def serve_photo(filename: str):
    photo_path = UPLOAD_DIR / f"photos/{filename}"
    if not photo_path.exists(): raise HTTPException(404)
    return FileResponse(str(photo_path))

# ── LinkedIn OAuth ───────────────────────────────────────────────────────
@app.get("/api/auth/linkedin")
async def linkedin_auth(user=Depends(require_auth)):
    if not LINKEDIN_CLIENT_ID: raise HTTPException(501, "LinkedIn nicht konfiguriert")
    state = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    redirect_uri = f"{APP_URL}/api/auth/linkedin/callback"
    url = (f"https://www.linkedin.com/oauth/v2/authorization?response_type=code"
           f"&client_id={LINKEDIN_CLIENT_ID}&redirect_uri={redirect_uri}"
           f"&state={state}&scope=openid%20profile%20email")
    return {"auth_url": url, "state": state}

@app.get("/api/auth/linkedin/callback")
async def linkedin_callback(code: str = "", state: str = "", error: str = ""):
    err_msg = error or "cancelled"
    if error or not code:
        return HTMLResponse(f"<script>window.opener.postMessage({{type:'linkedin_error',error:'{err_msg}'}},'*');window.close();</script>")
    redirect_uri = f"{APP_URL}/api/auth/linkedin/callback"
    import urllib.request, urllib.parse, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    # Exchange code for token
    try:
        token_data = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "client_id": LINKEDIN_CLIENT_ID, "client_secret": LINKEDIN_CLIENT_SECRET}).encode()
        req = urllib.request.Request("https://www.linkedin.com/oauth/v2/accessToken", data=token_data, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "BEATRIXLab/3.5"})
        token_resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        access_token = token_resp["access_token"]
    except Exception as e:
        logger.error(f"LinkedIn token exchange failed: {e}")
        return HTMLResponse(f"<script>window.opener.postMessage({{type:'linkedin_error',error:'token_exchange_failed'}},'*');window.close();</script>")
    # Fetch profile using OpenID userinfo
    try:
        req = urllib.request.Request("https://api.linkedin.com/v2/userinfo", headers={"Authorization": f"Bearer {access_token}", "User-Agent": "BEATRIXLab/3.5"})
        profile = json.loads(urllib.request.urlopen(req, context=ctx).read())
    except Exception as e:
        logger.error(f"LinkedIn profile fetch failed: {e}")
        return HTMLResponse(f"<script>window.opener.postMessage({{type:'linkedin_error',error:'profile_fetch_failed'}},'*');window.close();</script>")
    linkedin_data = {
        "sub": profile.get("sub", ""),
        "name": profile.get("name", ""),
        "given_name": profile.get("given_name", ""),
        "family_name": profile.get("family_name", ""),
        "email": profile.get("email", ""),
        "picture": profile.get("picture", ""),
    }
    return HTMLResponse(f"<script>window.opener.postMessage({{type:'linkedin_success',data:{json.dumps(linkedin_data)}}},'*');window.close();</script>")

@app.post("/api/profile/linkedin")
async def save_linkedin_data(data: dict, user=Depends(require_auth)):
    db = get_db()
    try:
        u = db.query(User).filter(User.email == user["sub"]).first()
        if not u: raise HTTPException(404)
        if data.get("sub"): u.linkedin_id = str(data["sub"])
        if data.get("name") and not u.name: u.name = data["name"]
        if data.get("picture"): u.profile_photo_url = data["picture"]
        db.commit()
        return {"message": "LinkedIn-Daten gespeichert", "linkedin_connected": True}
    finally: db.close()

@app.post("/api/profile/linkedin/disconnect")
async def disconnect_linkedin(user=Depends(require_auth)):
    db = get_db()
    try:
        u = db.query(User).filter(User.email == user["sub"]).first()
        if not u: raise HTTPException(404)
        u.linkedin_id = None
        db.commit()
        return {"message": "LinkedIn getrennt"}
    finally: db.close()

# ── Behavioral Insights / Ψ-Profiling ──────────────────────────────────

INSIGHT_QUESTION_POOL = [
    {"id": "iq-001", "text": "Wenn du eine Entscheidung unter Unsicherheit triffst — worauf verlässt du dich?", "category": "decision_style", "domain": "ORG",
     "choices": [
        {"icon": "📊", "label": "Daten & Evidenz", "signal": {"style": "analytical", "domain": "FIN"}},
        {"icon": "🧭", "label": "Intuition & Erfahrung", "signal": {"style": "intuitive", "domain": "ORG"}},
        {"icon": "⚖️", "label": "Beides — je nach Kontext", "signal": {"style": "adaptive", "domain": "ORG"}},
        {"icon": "🗣️", "label": "Ich frage mein Netzwerk", "signal": {"style": "social", "domain": "ORG"}},
        {"icon": "🎲", "label": "Ich entscheide schnell und korrigiere", "signal": {"style": "experimental", "domain": "ORG"}},
     ]},
    {"id": "iq-002", "text": "Welches Verhaltensphänomen fasziniert dich am meisten?", "category": "interest_probe", "domain": "FIN",
     "choices": [
        {"icon": "💰", "label": "Warum Menschen nicht sparen", "signal": {"style": "practical", "domain": "FIN"}},
        {"icon": "🏥", "label": "Warum wir ungesund leben", "signal": {"style": "practical", "domain": "HLT"}},
        {"icon": "🌍", "label": "Warum Gesellschaften nicht handeln beim Klima", "signal": {"style": "systemic", "domain": "ENV"}},
        {"icon": "🏢", "label": "Warum Organisationen sich nicht verändern", "signal": {"style": "structural", "domain": "ORG"}},
        {"icon": "🕊️", "label": "Wie Glaube und Kultur Entscheidungen formen", "signal": {"style": "cultural", "domain": "REL"}},
     ]},
    {"id": "iq-003", "text": "Du darfst ein Nudge-Experiment weltweit durchführen — welchen Bereich wählst du?", "category": "domain_preference", "domain": "HLT",
     "choices": [
        {"icon": "🏥", "label": "Gesundheit & Prävention", "signal": {"style": "practical", "domain": "HLT"}},
        {"icon": "💰", "label": "Finanzen & Altersvorsorge", "signal": {"style": "practical", "domain": "FIN"}},
        {"icon": "🌱", "label": "Umwelt & Nachhaltigkeit", "signal": {"style": "visionary", "domain": "ENV"}},
        {"icon": "🎓", "label": "Bildung & Lernen", "signal": {"style": "developmental", "domain": "EDU"}},
        {"icon": "🏛️", "label": "Demokratie & Partizipation", "signal": {"style": "systemic", "domain": "POL"}},
     ]},
    {"id": "iq-004", "text": "Was ist der wichtigste Hebel für Verhaltensänderung?", "category": "theory_preference", "domain": "ORG",
     "choices": [
        {"icon": "💡", "label": "Die richtige Information", "signal": {"style": "rational", "domain": "EDU"}},
        {"icon": "🏗️", "label": "Die richtige Architektur", "signal": {"style": "structural", "domain": "ORG"}},
        {"icon": "⏰", "label": "Der richtige Zeitpunkt", "signal": {"style": "contextual", "domain": "ORG"}},
        {"icon": "👥", "label": "Die richtigen sozialen Normen", "signal": {"style": "social", "domain": "ORG"}},
        {"icon": "❤️", "label": "Die richtige Motivation", "signal": {"style": "motivational", "domain": "ORG"}},
     ]},
    {"id": "iq-005", "text": "Zwei Strategien stehen zur Wahl — welche nimmst du?", "category": "risk_preference", "domain": "FIN",
     "choices": [
        {"icon": "🎯", "label": "70% sicher, moderater Impact", "signal": {"style": "risk_averse", "domain": "FIN"}},
        {"icon": "🚀", "label": "30% aber 10x Impact", "signal": {"style": "risk_seeking", "domain": "FIN"}},
        {"icon": "🔄", "label": "Sequenziell testen, dann skalieren", "signal": {"style": "experimental", "domain": "ORG"}},
        {"icon": "🤝", "label": "Beide kombinieren als Portfolio", "signal": {"style": "portfolio", "domain": "FIN"}},
        {"icon": "📋", "label": "Mehr Daten sammeln bevor ich entscheide", "signal": {"style": "analytical", "domain": "FIN"}},
     ]},
    {"id": "iq-006", "text": "Prägen kulturelle Werte das wirtschaftliche Verhalten stärker als Anreize?", "category": "worldview", "domain": "REL",
     "choices": [
        {"icon": "🕊️", "label": "Ja — Kultur ist der tiefste Treiber", "signal": {"style": "cultural", "domain": "REL"}},
        {"icon": "📈", "label": "Nein — Anreize dominieren immer", "signal": {"style": "economic", "domain": "FIN"}},
        {"icon": "🔀", "label": "Es ist komplementär", "signal": {"style": "integrative", "domain": "REL"}},
        {"icon": "🔬", "label": "Kommt auf den Kontext an", "signal": {"style": "contextual", "domain": "ORG"}},
        {"icon": "🧬", "label": "Biologie und Evolution prägen am stärksten", "signal": {"style": "evolutionary", "domain": "HLT"}},
     ]},
    {"id": "iq-007", "text": "Welcher Auftrag wäre am spannendsten für dich?", "category": "scope_preference", "domain": "POL",
     "choices": [
        {"icon": "🏛️", "label": "Eine Regierung beraten", "signal": {"style": "macro", "domain": "POL"}},
        {"icon": "🚀", "label": "Ein Startup transformieren", "signal": {"style": "micro", "domain": "ORG"}},
        {"icon": "🌐", "label": "Multilaterale Organisation (UN, WHO)", "signal": {"style": "global", "domain": "POL"}},
        {"icon": "🏦", "label": "Eine Grossbank neu denken", "signal": {"style": "structural", "domain": "FIN"}},
        {"icon": "🎓", "label": "Ein Bildungssystem redesignen", "signal": {"style": "developmental", "domain": "EDU"}},
     ]},
    {"id": "iq-008", "text": "Willingness, Ability, Capacity — wo scheitern die meisten Veränderungsprojekte?", "category": "bcm_understanding", "domain": "ORG",
     "choices": [
        {"icon": "❤️", "label": "Willingness — die Bereitschaft fehlt", "signal": {"style": "motivational", "domain": "ORG"}},
        {"icon": "🧠", "label": "Ability — die Fähigkeit fehlt", "signal": {"style": "capability", "domain": "EDU"}},
        {"icon": "🏗️", "label": "Capacity — die Struktur verhindert es", "signal": {"style": "structural", "domain": "ORG"}},
        {"icon": "🔗", "label": "Am Zusammenspiel aller drei", "signal": {"style": "systemic", "domain": "ORG"}},
        {"icon": "📏", "label": "Am falschen Messen — man weiss nicht wo", "signal": {"style": "analytical", "domain": "ORG"}},
     ]},
    {"id": "iq-009", "text": "Wie sollte ein gutes Verhaltensmodell sein?", "category": "abstraction_preference", "domain": "EDU",
     "choices": [
        {"icon": "🔢", "label": "Mathematisch präzise", "signal": {"style": "formal", "domain": "FIN"}},
        {"icon": "🎨", "label": "Intuitiv verständlich", "signal": {"style": "intuitive", "domain": "EDU"}},
        {"icon": "🔬", "label": "Empirisch validiert", "signal": {"style": "empirical", "domain": "ORG"}},
        {"icon": "🛠️", "label": "Direkt anwendbar in der Praxis", "signal": {"style": "practical", "domain": "ORG"}},
        {"icon": "🌊", "label": "Flexibel und kontextabhängig", "signal": {"style": "adaptive", "domain": "ORG"}},
     ]},
    {"id": "iq-010", "text": "Welches Bias ist am gefährlichsten in strategischen Entscheidungen?", "category": "bias_awareness", "domain": "ORG",
     "choices": [
        {"icon": "🦚", "label": "Overconfidence", "signal": {"style": "metacognitive", "domain": "ORG"}},
        {"icon": "🪨", "label": "Status Quo Bias", "signal": {"style": "structural", "domain": "ORG"}},
        {"icon": "💸", "label": "Sunk Cost Fallacy", "signal": {"style": "economic", "domain": "FIN"}},
        {"icon": "👥", "label": "Groupthink", "signal": {"style": "social", "domain": "ORG"}},
        {"icon": "🔍", "label": "Confirmation Bias", "signal": {"style": "analytical", "domain": "ORG"}},
     ]},
    {"id": "iq-011", "text": "Wenn du ein Behavioral Design Projekt startest — womit beginnst du?", "category": "design_approach", "domain": "ORG",
     "choices": [
        {"icon": "👤", "label": "Mit der Zielgruppe verstehen", "signal": {"style": "empathic", "domain": "ORG"}},
        {"icon": "🎯", "label": "Mit dem gewünschten Verhalten", "signal": {"style": "goal_oriented", "domain": "ORG"}},
        {"icon": "📊", "label": "Mit der Datenlage", "signal": {"style": "analytical", "domain": "FIN"}},
        {"icon": "🗺️", "label": "Mit der Entscheidungsumgebung", "signal": {"style": "structural", "domain": "ORG"}},
        {"icon": "📚", "label": "Mit der Literatur und Evidenz", "signal": {"style": "theoretical", "domain": "EDU"}},
     ]},
    {"id": "iq-012", "text": "Was treibt Unternehmen stärker?", "category": "motivation_theory", "domain": "FIN",
     "choices": [
        {"icon": "📈", "label": "Der Wunsch nach Wachstum", "signal": {"style": "growth", "domain": "FIN"}},
        {"icon": "🛡️", "label": "Die Angst vor Verlust", "signal": {"style": "loss_averse", "domain": "FIN"}},
        {"icon": "🏆", "label": "Der Wettbewerb mit anderen", "signal": {"style": "competitive", "domain": "ORG"}},
        {"icon": "🔄", "label": "Der Druck sich anzupassen", "signal": {"style": "adaptive", "domain": "ORG"}},
        {"icon": "💡", "label": "Die Vision einzelner Führungspersonen", "signal": {"style": "visionary", "domain": "ORG"}},
     ]},
]

@app.get("/api/insight/question")
async def get_insight_question(context: str = "login", user=Depends(require_auth)):
    """Get next insight question for user. Returns question + metadata about what's expected."""
    db = get_db()
    try:
        email = user["sub"]
        # Count how many insights this user already has
        total_insights = db.execute(text("SELECT COUNT(*) FROM user_insights WHERE user_email = :e"), {"e": email}).scalar() or 0
        # Count insights in current session (last 10 minutes)
        session_insights = db.execute(text(
            "SELECT COUNT(*) FROM user_insights WHERE user_email = :e AND created_at > NOW() - INTERVAL '10 minutes'"
        ), {"e": email}).scalar() or 0

        # Determine question number and mandatory/nudge status
        q_number = session_insights + 1
        is_mandatory = q_number <= 1
        is_nudged = q_number in [2, 3]
        is_voluntary = q_number >= 4

        # Get IDs of already-answered questions
        answered = db.execute(text(
            "SELECT question_text FROM user_insights WHERE user_email = :e AND skipped = FALSE"
        ), {"e": email}).fetchall()
        answered_texts = {r[0] for r in answered}

        # Pick a question not yet answered, personalized by profile
        profile = db.query(User).filter(User.email == email).first()
        expertise = (profile.expertise or []) if profile else []

        # Prioritize questions matching user expertise domains
        domain_map = {
            "Behavioral Economics": ["FIN", "ORG"],
            "Strategy": ["ORG", "POL"],
            "Decision Architecture": ["ORG", "FIN"],
            "Healthcare": ["HLT"],
            "Finance": ["FIN"],
            "Education": ["EDU"],
            "Religion": ["REL"],
            "Environment": ["ENV"],
            "Politics": ["POL"],
        }
        preferred_domains = set()
        for exp in expertise:
            for key, domains in domain_map.items():
                if key.lower() in exp.lower():
                    preferred_domains.update(domains)
        if not preferred_domains:
            preferred_domains = {"ORG", "FIN"}

        # Sort: preferred domain first, then others
        available = [q for q in INSIGHT_QUESTION_POOL if q["text"] not in answered_texts]
        if not available:
            available = INSIGHT_QUESTION_POOL  # Reset if all answered

        preferred = [q for q in available if q["domain"] in preferred_domains]
        other = [q for q in available if q["domain"] not in preferred_domains]

        random.shuffle(preferred)
        random.shuffle(other)
        ordered = preferred + other
        question = ordered[0] if ordered else INSIGHT_QUESTION_POOL[0]

        # Nudge messages
        nudge_msg = None
        if is_nudged:
            nudges = [
                "Noch eine Frage? Hilft BEATRIX, dich besser zu verstehen.",
                "Eine weitere Frage stärkt dein Ψ-Profil.",
                "Je mehr BEATRIX über deinen Denkstil weiss, desto besser die Modelle.",
            ]
            nudge_msg = random.choice(nudges)

        return {
            "question": question["text"],
            "question_id": question["id"],
            "category": question["category"],
            "choices": [{"icon": c["icon"], "label": c["label"]} for c in question.get("choices", [])],
            "question_number": q_number,
            "is_mandatory": is_mandatory,
            "is_nudged": is_nudged,
            "is_voluntary": is_voluntary,
            "nudge_message": nudge_msg,
            "total_answered": total_insights,
            "can_skip": not is_mandatory,
            "session_number": total_insights + 1,
        }
    except Exception as e:
        logger.error(f"Insight question error: {e}")
        # Fallback
        fallback_q = INSIGHT_QUESTION_POOL[0]
        return {
            "question": fallback_q["text"],
            "question_id": fallback_q["id"],
            "category": fallback_q["category"],
            "choices": [{"icon": c["icon"], "label": c["label"]} for c in fallback_q.get("choices", [])],
            "question_number": 1, "is_mandatory": True, "is_nudged": False,
            "is_voluntary": False, "nudge_message": None, "total_answered": 0,
            "can_skip": False, "session_number": 1,
        }
    finally: db.close()

class InsightAnswer(BaseModel):
    question_text: str
    question_id: Optional[str] = None
    answer_text: str
    choice_index: Optional[int] = None
    latency_ms: Optional[int] = None
    question_number: int = 1
    was_mandatory: bool = True
    was_nudged: bool = False
    skipped: bool = False
    context: str = "login"

@app.post("/api/insight/answer")
async def submit_insight_answer(request: InsightAnswer, user=Depends(require_auth)):
    """Submit answer to an insight question. Extracts behavioral metadata."""
    db = get_db()
    try:
        email = user["sub"]

        # Extract behavioral signals from the selected choice
        domain_signal = None
        thinking_style = None
        abstraction_level = "concise"  # Choice clicks are always concise
        autonomy_signal = "moderate"

        # Look up signal from question pool based on question_id and choice_index
        question_data = None
        for q in INSIGHT_QUESTION_POOL:
            if q["id"] == request.question_id:
                question_data = q; break

        if question_data and request.choice_index and question_data.get("choices"):
            idx = request.choice_index - 1  # 1-based to 0-based
            if 0 <= idx < len(question_data["choices"]):
                chosen = question_data["choices"][idx]
                signal = chosen.get("signal", {})
                domain_signal = signal.get("domain")
                thinking_style = signal.get("style")

        # Latency adds decision speed signal
        speed_suffix = ""
        if request.latency_ms and request.latency_ms < 3000:
            speed_suffix = "_fast"
        elif request.latency_ms and request.latency_ms > 20000:
            speed_suffix = "_deliberate"
        if thinking_style and speed_suffix:
            thinking_style = thinking_style + speed_suffix

        insight = UserInsight(
            user_email=email,
            question_text=request.question_text,
            question_category=request.question_id,
            answer_text=request.answer_text,
            choice_index=request.choice_index,
            latency_ms=request.latency_ms,
            session_number=1,  # TODO: calculate from login count
            question_number=request.question_number,
            was_mandatory=request.was_mandatory,
            was_nudged=request.was_nudged,
            skipped=request.skipped,
            domain_signal=domain_signal,
            thinking_style=thinking_style,
            abstraction_level=abstraction_level,
            autonomy_signal=autonomy_signal,
            context=request.context,
        )
        db.add(insight); db.commit()
        logger.info(f"Insight recorded: {email} q#{request.question_number} domain={domain_signal} style={thinking_style}")
        return {"status": "recorded", "domain_signal": domain_signal, "thinking_style": thinking_style}
    except Exception as e:
        db.rollback()
        logger.error(f"Insight answer error: {e}")
        raise HTTPException(500, f"Fehler: {e}")
    finally: db.close()

@app.get("/api/insight/profile")
async def get_insight_profile(user=Depends(require_auth)):
    """Get aggregated behavioral Ψ-profile for user."""
    db = get_db()
    try:
        email = user["sub"]
        insights = db.execute(text(
            "SELECT * FROM user_insights WHERE user_email = :e ORDER BY created_at DESC"
        ), {"e": email}).fetchall()

        if not insights:
            return {"has_profile": False, "total_insights": 0, "message": "Noch kein Ψ-Profil. Beantworte Fragen um dein Profil aufzubauen."}

        # Aggregate signals
        domains = {}
        styles = {}
        abstractions = {}
        autonomy_signals = {}
        total_latency = []
        voluntary_count = 0

        for row in insights:
            r = dict(row._mapping)
            if r.get("domain_signal"):
                domains[r["domain_signal"]] = domains.get(r["domain_signal"], 0) + 1
            if r.get("thinking_style"):
                base_style = r["thinking_style"].split("_")[0]
                styles[base_style] = styles.get(base_style, 0) + 1
            if r.get("abstraction_level"):
                abstractions[r["abstraction_level"]] = abstractions.get(r["abstraction_level"], 0) + 1
            if r.get("autonomy_signal"):
                autonomy_signals[r["autonomy_signal"]] = autonomy_signals.get(r["autonomy_signal"], 0) + 1
            if r.get("latency_ms"):
                total_latency.append(r["latency_ms"])
            if not r.get("was_mandatory") and not r.get("was_nudged") and not r.get("skipped"):
                voluntary_count += 1

        # Primary signals
        primary_domain = max(domains, key=domains.get) if domains else None
        primary_style = max(styles, key=styles.get) if styles else None
        avg_latency = sum(total_latency) / len(total_latency) if total_latency else None

        # Engagement score (0-100)
        engagement = min(100, len(insights) * 10 + voluntary_count * 15)

        return {
            "has_profile": True,
            "total_insights": len(insights),
            "primary_domain": primary_domain,
            "domain_distribution": domains,
            "primary_thinking_style": primary_style,
            "thinking_styles": styles,
            "abstraction_distribution": abstractions,
            "autonomy_distribution": autonomy_signals,
            "avg_decision_latency_ms": round(avg_latency) if avg_latency else None,
            "voluntary_answers": voluntary_count,
            "engagement_score": engagement,
            "decision_speed": "fast" if avg_latency and avg_latency < 5000 else "deliberate" if avg_latency and avg_latency > 20000 else "moderate",
            "answers": [
                {
                    "question": dict(row._mapping).get("question_text", ""),
                    "answer": dict(row._mapping).get("answer_text", ""),
                    "choice_index": dict(row._mapping).get("choice_index"),
                    "domain": dict(row._mapping).get("domain_signal"),
                    "style": dict(row._mapping).get("thinking_style"),
                    "latency_ms": dict(row._mapping).get("latency_ms"),
                    "created_at": str(dict(row._mapping).get("created_at", "")),
                }
                for row in insights if not dict(row._mapping).get("skipped")
            ],
        }
    except Exception as e:
        logger.error(f"Insight profile error: {e}")
        return {"has_profile": False, "total_insights": 0, "error": str(e)}
    finally: db.close()

@app.post("/api/insight/skip")
async def skip_insight_question(data: dict, user=Depends(require_auth)):
    """Record that user skipped a question."""
    db = get_db()
    try:
        insight = UserInsight(
            user_email=user["sub"],
            question_text=data.get("question_text", ""),
            question_category=data.get("question_id"),
            skipped=True,
            question_number=data.get("question_number", 1),
            was_mandatory=False,
            context=data.get("context", "login"),
        )
        db.add(insight); db.commit()
        return {"status": "skipped"}
    except Exception as e:
        db.rollback()
        return {"status": "error", "detail": str(e)}
    finally: db.close()

@app.post("/api/forgot-password")
async def forgot_password(request: ResetPasswordRequest):
    email = request.email.strip().lower()
    db = get_db()
    try:
        user = db.query(User).filter(User.email == email).first()
        # Always return success to prevent email enumeration
        if not user:
            return {"message": "Falls ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link gesendet."}
        if not user.is_active:
            return {"message": "Falls ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link gesendet."}
        # Rate limit: max once every 2 minutes
        if user.reset_sent_at and (datetime.utcnow() - user.reset_sent_at).total_seconds() < 120:
            raise HTTPException(429, "Bitte warte 2 Minuten, bevor du einen neuen Link anforderst.")
        reset_token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        user.reset_token = reset_token
        user.reset_sent_at = datetime.utcnow()
        db.commit()
        sent = send_reset_email(email, user.name, reset_token)
        if not sent:
            logger.warning(f"Reset email failed for {email}")
        return {"message": "Falls ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link gesendet."}
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, f"Fehler: {e}")
    finally: db.close()

@app.get("/api/reset/{token}")
async def reset_page(token: str):
    db = get_db()
    try:
        user = db.query(User).filter(User.reset_token == token).first()
        if not user:
            html = _verify_page("Ungültiger Link", "Dieser Reset-Link ist ungültig oder wurde bereits verwendet.", False)
            return HTMLResponse(html)
        if user.reset_sent_at and (datetime.utcnow() - user.reset_sent_at).total_seconds() > 3600:
            html = _verify_page("Link abgelaufen", "Dieser Reset-Link ist abgelaufen. Bitte fordere einen neuen an.", False)
            return HTMLResponse(html)
        return HTMLResponse(_reset_page(token))
    finally: db.close()

@app.post("/api/reset-password")
async def reset_password(request: ResetPasswordConfirm):
    db = get_db()
    try:
        user = db.query(User).filter(User.reset_token == request.token).first()
        if not user: raise HTTPException(400, "Ungültiger oder abgelaufener Link")
        if user.reset_sent_at and (datetime.utcnow() - user.reset_sent_at).total_seconds() > 3600:
            raise HTTPException(400, "Link abgelaufen. Bitte fordere einen neuen an.")
        if len(request.new_password) < 6:
            raise HTTPException(400, "Passwort muss mindestens 6 Zeichen haben")
        pw_hash, pw_salt = hash_password(request.new_password)
        user.password_hash = pw_hash; user.password_salt = pw_salt
        user.reset_token = None; user.reset_sent_at = None; db.commit()
        logger.info(f"Password reset: {user.email}")
        return {"message": "Passwort erfolgreich zurückgesetzt"}
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, f"Fehler: {e}")
    finally: db.close()

def _verify_page(title, message, success):
    color = "#34d399" if success else "#f87171"
    icon = "✓" if success else "✗"
    return f"""<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title} – BEATRIX Lab</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{{font-family:'Plus Jakarta Sans',sans-serif;background:#0a1628;color:#e4e9f2;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{max-width:440px;padding:48px 40px;text-align:center}}
.icon{{font-size:56px;margin-bottom:20px;color:{color}}}
h1{{font-size:24px;font-weight:800;margin-bottom:12px}}h1 span{{color:#5b8af5}}
p{{font-size:15px;color:#8899b8;line-height:1.6;margin-bottom:28px}}
a{{display:inline-block;padding:14px 36px;background:#5b8af5;color:white;text-decoration:none;border-radius:10px;font-weight:700;font-size:15px}}
a:hover{{background:#7ba3ff}}</style></head>
<body><div class="card"><div class="icon">{icon}</div><h1>BEATRIX <span>Lab</span></h1><h2>{title}</h2><p>{message}</p>
<a href="{APP_URL}">Zum Login →</a></div></body></html>"""

def _reset_page(token):
    return f"""<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Passwort zurücksetzen – BEATRIX Lab</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
<style>body{{font-family:'Plus Jakarta Sans',sans-serif;background:#0a1628;color:#e4e9f2;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{max-width:440px;padding:48px 40px;text-align:center}}
h1{{font-size:24px;font-weight:800;margin-bottom:8px}}h1 span{{color:#5b8af5}}
p{{font-size:14px;color:#8899b8;margin-bottom:24px}}
input{{width:100%;padding:14px;background:#111d33;border:1px solid #1e2d4a;border-radius:10px;color:#e4e9f2;font-family:inherit;font-size:15px;outline:none;margin-bottom:12px;box-sizing:border-box}}
input:focus{{border-color:#5b8af5;box-shadow:0 0 0 3px rgba(91,138,245,0.15)}}
button{{width:100%;padding:14px;background:#5b8af5;color:white;border:none;border-radius:10px;font-weight:700;font-size:15px;cursor:pointer;font-family:inherit}}
button:hover{{background:#7ba3ff}}
.msg{{font-size:13px;padding:10px;border-radius:8px;margin-bottom:12px;display:none}}
.msg.error{{display:block;color:#f87171;background:rgba(248,113,113,0.08)}}
.msg.success{{display:block;color:#34d399;background:rgba(52,211,153,0.08)}}
</style></head>
<body><div class="card">
<h1>BEATRIX <span>Lab</span></h1>
<p>Neues Passwort festlegen</p>
<div class="msg" id="msg"></div>
<input type="password" id="pw1" placeholder="Neues Passwort (mind. 6 Zeichen)">
<input type="password" id="pw2" placeholder="Passwort bestätigen">
<button onclick="resetPw()">Passwort speichern</button>
<script>
async function resetPw() {{
    const pw1=document.getElementById('pw1').value, pw2=document.getElementById('pw2').value, msg=document.getElementById('msg');
    msg.className='msg';
    if(pw1.length<6){{msg.className='msg error';msg.textContent='Mind. 6 Zeichen';return}}
    if(pw1!==pw2){{msg.className='msg error';msg.textContent='Passwörter stimmen nicht überein';return}}
    try{{
        const r=await fetch('/api/reset-password',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token:'{token}',new_password:pw1}})}});
        const d=await r.json();
        if(r.ok){{msg.className='msg success';msg.textContent='✓ Passwort geändert! Du wirst weitergeleitet...';setTimeout(()=>window.location.href='{APP_URL}',2000)}}
        else{{msg.className='msg error';msg.textContent=d.detail||'Fehler'}}
    }}catch(e){{msg.className='msg error';msg.textContent='Verbindungsfehler'}}
}}
</script>
</div></body></html>"""

def send_reset_email(email, name, token):
    """Send password reset email via Resend API"""
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set, skipping reset email")
        return False
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    reset_url = f"{APP_URL}/api/reset/{token}"
    html = f"""<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:40px 24px">
    <div style="text-align:center;margin-bottom:32px">
        <h1 style="font-size:24px;font-weight:800;color:#0a1628;margin:0">BEATRIX <span style="color:#5b8af5">Lab</span></h1>
        <p style="color:#666;font-size:14px;margin:8px 0 0">Strategic Intelligence Suite</p>
    </div>
    <p style="font-size:15px;color:#333">Hallo {name or 'dort'},</p>
    <p style="font-size:15px;color:#333;line-height:1.6">Du hast ein neues Passwort für dein BEATRIX Lab Konto angefordert:</p>
    <div style="text-align:center;margin:32px 0">
        <a href="{reset_url}" style="display:inline-block;padding:14px 36px;background:#5b8af5;color:white;text-decoration:none;border-radius:10px;font-weight:700;font-size:15px">Passwort zurücksetzen</a>
    </div>
    <p style="font-size:12px;color:#999;line-height:1.5">Falls du kein neues Passwort angefordert hast, ignoriere diese E-Mail.<br>
    <a href="{reset_url}" style="color:#5b8af5;word-break:break-all">{reset_url}</a></p>
    <p style="font-size:12px;color:#999;margin-top:24px">Dieser Link ist 1 Stunde gültig.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:32px 0">
    <p style="font-size:11px;color:#aaa;text-align:center">FehrAdvice &amp; Partners AG · Zürich</p>
</div>"""
    payload = json.dumps({
        "from": EMAIL_FROM,
        "to": [email],
        "subject": "BEATRIX Lab – Passwort zurücksetzen",
        "html": html,
        "text": f"Hallo {name},\n\nSetze dein Passwort zurück: {reset_url}\n\nDieser Link ist 1 Stunde gültig."
    }).encode()
    try:
        req = urllib.request.Request("https://api.resend.com/emails", data=payload, method="POST",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json", "User-Agent": "BEATRIXLab/3.4"})
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        logger.info(f"Reset email sent to {email} via Resend: {resp.get('id','?')}")
        return True
    except Exception as e:
        logger.error(f"Failed to send reset email to {email}: {e}")
        return False

from fastapi.responses import HTMLResponse

@app.get("/api/auth/check")
async def check_auth(user=Depends(require_auth)):
    return {"authenticated": True, "email": user.get("sub"), "name": user.get("name")}

@app.get("/api/health")
async def health():
    db_ok = False
    try: db = get_db(); db.close(); db_ok = True
    except: pass
    return {"status": "ok" if db_ok else "degraded", "database": "connected" if db_ok else "unavailable", "github": "configured" if GH_TOKEN else "not configured", "github_repo": GH_REPO, "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/admin/settings")
async def admin_settings(user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    return {"allowed_email_domains": ALLOWED_EMAIL_DOMAINS or ["*"], "registration": "restricted" if ALLOWED_EMAIL_DOMAINS else "open", "jwt_expiry_hours": JWT_EXPIRY // 3600, "email_verification": REQUIRE_EMAIL_VERIFICATION, "smtp_configured": bool(RESEND_API_KEY)}

@app.get("/api/admin/users")
async def admin_users(user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        return [{"id": u.id, "email": u.email, "name": u.name, "is_active": u.is_active, "is_admin": u.is_admin, "role": u.role or "researcher", "email_verified": u.email_verified, "crm_access": u.crm_access or False, "crm_role": u.crm_role or "none", "crm_owner_code": u.crm_owner_code or "", "lead_management": getattr(u, 'lead_management', False) or False, "created_at": u.created_at.isoformat() if u.created_at else None, "last_login": u.last_login.isoformat() if u.last_login else None} for u in users]
    finally: db.close()

@app.put("/api/admin/users/{user_id}/toggle-active")
async def toggle_user_active(user_id: str, user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        target = db.query(User).filter(User.id == user_id).first()
        if not target: raise HTTPException(404, "Benutzer nicht gefunden")
        target.is_active = not target.is_active; db.commit()
        return {"email": target.email, "is_active": target.is_active}
    finally: db.close()

@app.put("/api/admin/users/{user_id}/role")
async def set_user_role(user_id: str, request: Request, user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        data = await request.json()
        role = data.get("role", "researcher")
        if role not in ("researcher", "sales", "operations", "senior_management", "partner"):
            raise HTTPException(400, "Ungültige Rolle")
        target = db.query(User).filter(User.id == user_id).first()
        if not target: raise HTTPException(404, "Benutzer nicht gefunden")
        target.role = role
        # Auto-enable CRM for senior roles (if @fehradvice.com)
        if role in ("senior_management", "partner") and target.email.lower().endswith("@fehradvice.com"):
            if not target.crm_access:
                target.crm_access = True
                target.lead_management = True
                if not target.crm_role or target.crm_role == "none":
                    target.crm_role = "manager"
                logger.info(f"Auto-enabled CRM for senior role: {target.email}")
        db.commit()
        logger.info(f"Role changed: {target.email} → {role}")
        return {"email": target.email, "role": role, "crm_access": target.crm_access or False}
    finally: db.close()

@app.put("/api/admin/users/{user_id}/crm-access")
async def set_user_crm_access(user_id: str, request: Request, user=Depends(require_auth)):
    """Toggle CRM access for a user. Only admins. Only @fehradvice.com emails eligible."""
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        data = await request.json()
        target = db.query(User).filter(User.id == user_id).first()
        if not target: raise HTTPException(404, "Benutzer nicht gefunden")
        if not target.email.lower().endswith("@fehradvice.com"):
            raise HTTPException(400, "CRM nur für FehrAdvice-Mitarbeiter verfügbar")
        if "crm_access" in data:
            target.crm_access = bool(data["crm_access"])
        if "crm_role" in data:
            if data["crm_role"] not in ("none", "viewer", "manager", "admin"):
                raise HTTPException(400, "Ungültige CRM-Rolle")
            target.crm_role = data["crm_role"]
        if "crm_owner_code" in data:
            target.crm_owner_code = data["crm_owner_code"] or None
        if "lead_management" in data:
            target.lead_management = bool(data["lead_management"])
        db.commit()
        logger.info(f"CRM access changed: {target.email} → access={target.crm_access}, role={target.crm_role}, owner={target.crm_owner_code}, leads={target.lead_management}")
        return {"email": target.email, "crm_access": target.crm_access, "crm_role": target.crm_role, "crm_owner_code": target.crm_owner_code, "lead_management": target.lead_management or False}
    finally: db.close()

@app.put("/api/admin/users/{user_id}/reset-password")
async def admin_reset_password(user_id: str, request: Request, user=Depends(require_auth)):
    """Admin resets a user's password."""
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        data = await request.json()
        new_pw = data.get("password", "")
        if len(new_pw) < 8: raise HTTPException(400, "Passwort muss mindestens 8 Zeichen haben")
        target = db.query(User).filter(User.id == user_id).first()
        if not target: raise HTTPException(404, "Benutzer nicht gefunden")
        pw_hash, pw_salt = hash_password(new_pw)
        target.password_hash = pw_hash
        target.password_salt = pw_salt
        db.commit()
        logger.info(f"Admin password reset: {target.email}")
        return {"email": target.email, "status": "password_reset"}
    finally: db.close()

@app.put("/api/admin/users/{user_id}/toggle-admin")
async def admin_toggle_admin(user_id: str, request: Request, user=Depends(require_auth)):
    """Promote/demote a user to/from admin. Only existing admins can do this."""
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        data = await request.json()
        target = db.query(User).filter(User.id == user_id).first()
        if not target: raise HTTPException(404, "Benutzer nicht gefunden")
        # Don't allow removing own admin
        if target.email.lower() == user.get("sub", "").lower() and not data.get("is_admin", True):
            raise HTTPException(400, "Eigenen Admin-Status kann man nicht entfernen")
        target.is_admin = bool(data.get("is_admin", False))
        # Auto-enable CRM for new FehrAdvice admins
        if target.is_admin and target.email.lower().endswith("@fehradvice.com"):
            target.crm_access = True
            if not target.crm_role or target.crm_role == "none":
                target.crm_role = "admin"
        db.commit()
        logger.info(f"Admin toggle: {target.email} → admin={target.is_admin}")
        return {"email": target.email, "is_admin": target.is_admin}
    finally: db.close()

# ── BEATRIX Chat (RAG) ──────────────────────────────────────────────────
class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email = Column(String(320), nullable=False, index=True)
    role = Column(String(20), nullable=False)  # "user" or "assistant"
    content = Column(Text, nullable=False)
    sources = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class ChatRequest(BaseModel):
    question: str
    database: Optional[str] = None

def search_knowledge_base(db, query: str, database: Optional[str] = None, limit: int = 8):
    """Three-tier hybrid search: Vector (if available) + PostgreSQL Fulltext + Keyword fallback."""
    
    # === TIER 1: Vector search via Voyage AI (best, if available) ===
    vector_results = vector_search(db, query, limit=limit) if VOYAGE_API_KEY else []

    # === TIER 2: PostgreSQL full-text search (great, always available) ===
    ft_results = fulltext_search(db, query, limit=limit)

    # === TIER 3: Keyword fallback (basic, always works) ===
    words = [w.lower() for w in query.split() if len(w) > 2]
    keyword_results = []
    if words:
        docs = db.query(Document).filter(Document.content.isnot(None))
        if database: docs = docs.filter(Document.database_target == database)
        docs = docs.all()
        for doc in docs:
            if not doc.content: continue
            text_lower = doc.content.lower()
            score = sum(text_lower.count(w) for w in words)
            if doc.title:
                score += sum(10 for w in words if w in doc.title.lower())
            if doc.tags:
                tags_lower = " ".join(doc.tags).lower()
                score += sum(5 for w in words if w in tags_lower)
            if doc.source_type == "ebf_answer":
                score = int(score * 3)
            if score > 0:
                keyword_results.append((score, doc))
        keyword_results.sort(key=lambda x: -x[0])

    # === MERGE: Combine all tiers ===
    merged = {}
    # Vector gets highest weight
    for score, doc in vector_results:
        merged[doc.id] = {"doc": doc, "score": score * 2.0}
    # Fulltext second
    for score, doc in ft_results:
        if doc.id in merged:
            merged[doc.id]["score"] += score
        else:
            merged[doc.id] = {"doc": doc, "score": score}
    # Keyword third
    max_kw = max((s for s, _ in keyword_results), default=1) or 1
    for score, doc in keyword_results:
        normalized = (score / max_kw) * 50  # Scale keyword to max 50
        if doc.id in merged:
            merged[doc.id]["score"] += normalized * 0.3
        else:
            merged[doc.id] = {"doc": doc, "score": normalized * 0.3}

    combined = [(m["score"], m["doc"]) for m in merged.values()]
    combined.sort(key=lambda x: -x[0])
    
    tiers_used = []
    if vector_results: tiers_used.append(f"vector:{len(vector_results)}")
    if ft_results: tiers_used.append(f"fulltext:{len(ft_results)}")
    if keyword_results: tiers_used.append(f"keyword:{len(keyword_results)}")
    logger.info(f"Hybrid search: {' + '.join(tiers_used)} → {len(combined)} combined results")
    
    return combined[:limit]

def build_context(results, max_chars=12000):
    """Build context string from search results."""
    context_parts = []
    total = 0
    for score, doc in results:
        text = doc.content or ""
        available = max_chars - total
        if available <= 0: break
        chunk = text[:available]
        source_info = f"[Quelle: {doc.title}"
        if doc.category: source_info += f", Kategorie: {doc.category}"
        if doc.tags: source_info += f", Tags: {', '.join(doc.tags)}"
        source_info += f", Typ: {doc.source_type}]"
        context_parts.append(f"{source_info}\n{chunk}")
        total += len(chunk) + len(source_info)
    return "\n\n---\n\n".join(context_parts)

def create_github_issue(question: str, user_email: str) -> dict:
    """Create a GitHub Issue on the context repo to trigger Claude Code."""
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    payload = json.dumps({
        "title": f"BEATRIX: {question[:100]}",
        "body": f"**Frage von:** {user_email}\n\n@claude {question}",
        "labels": ["beatrix-question"]
    }).encode()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{GH_CONTEXT_REPO}/issues",
        data=payload, method="POST",
        headers={"Authorization": f"token {GH_TOKEN}", "Content-Type": "application/json", "Accept": "application/vnd.github.v3+json"})
    resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
    return {"issue_number": resp["number"], "html_url": resp["html_url"]}

def poll_github_answer(issue_number: int) -> dict:
    """Poll a GitHub Issue for Claude Code's answer."""
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        f"https://api.github.com/repos/{GH_CONTEXT_REPO}/issues/{issue_number}/comments",
        headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"})
    comments = json.loads(urllib.request.urlopen(req, context=ctx).read())
    for comment in reversed(comments):
        login = comment.get("user", {}).get("login", "")
        body = comment.get("body", "")
        if login != "claude[bot]": continue
        if "Claude finished" in body:
            parts = body.split("---", 1)
            answer = parts[1].strip() if len(parts) > 1 else body
            return {"status": "done", "answer": answer, "comment_url": comment.get("html_url")}
        if "encountered an error" in body:
            return {"status": "error", "answer": "BEATRIX konnte die Analyse nicht abschliessen. Bitte versuche es erneut."}
        if "working" in body.lower() or "Working" in body:
            return {"status": "processing", "progress": body[:300]}
    return {"status": "waiting"}

def store_ebf_answer(db, question: str, answer: str, issue_url: str = ""):
    """Store a Claude Code EBF answer back into the Knowledge Base for fast retrieval."""
    # Extract keywords from question for tags
    stop_words = {"was", "ist", "das", "die", "der", "den", "dem", "ein", "eine", "wie", "und", "oder",
                  "von", "mit", "für", "auf", "aus", "bei", "nach", "über", "unter", "sind", "wird",
                  "kann", "hat", "haben", "sein", "werden", "nicht", "auch", "aber", "als", "nur",
                  "the", "what", "how", "are", "is", "in", "of", "and", "for", "to", "a", "an"}
    words = [w.strip("?!.,;:()[]") for w in question.split()]
    tags = list(set(w for w in words if len(w) > 2 and w.lower() not in stop_words))[:10]
    tags.append("ebf-answer")
    tags.append("claude-code")

    doc = Document(
        title=f"EBF: {question[:200]}",
        content=f"FRAGE: {question}\n\nANTWORT:\n{answer}",
        source_type="ebf_answer",
        database_target="knowledge_base",
        category="EBF Framework",
        tags=tags,
        status="indexed",
        github_url=issue_url,
        doc_metadata={"type": "ebf_cached_answer", "question": question, "generated_at": datetime.utcnow().isoformat()}
    )
    db.add(doc); db.commit()
    # Embed for vector search
    embed_document(db, doc.id)
    logger.info(f"EBF answer stored + embedded in KB: {question[:60]}")
    return doc.id

def fast_path_answer(question: str, context: str, sources: list) -> str:
    """Fast path: Use Claude API with existing KB context for instant answer."""
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

    system_prompt = """Du bist BEATRIX, die Strategic Intelligence Suite von FehrAdvice & Partners AG.
Du bist spezialisiert auf das Evidence-Based Framework (EBF), Behavioral Economics, das Behavioral Competence Model (BCM) und Decision Architecture.

Dir steht vorhandenes Wissen aus der BEATRIX Knowledge Base zur Verfügung. Dieses Wissen wurde zuvor durch tiefgehende Analyse des EBF-Frameworks erarbeitet.

Deine Aufgabe:
- Beantworte Fragen basierend auf dem bereitgestellten Kontext
- Antworte präzise, wissenschaftlich fundiert und praxisorientiert
- Nenne Quellen wenn du aus dem Kontext zitierst
- Wenn der Kontext nicht ausreicht, sage das ehrlich
- Antworte auf Deutsch, es sei denn die Frage ist auf Englisch

Stil: Professionell, klar, auf den Punkt. Wie ein Senior Berater bei FehrAdvice."""

    user_message = f"""Hier ist relevanter Kontext aus der BEATRIX Knowledge Base (vorberechnetes EBF-Wissen):

{context}

---

Frage: {question}"""

    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 3000,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_message}]
    }).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=payload, method="POST",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "User-Agent": "BEATRIXLab/3.8"
        })
    resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
    return resp["content"][0]["text"]

# Relevance threshold: minimum score to use fast path
FAST_PATH_THRESHOLD = 15

@app.post("/api/chat/stream")
async def chat_stream(request: ChatRequest, user=Depends(require_auth)):
    """SSE streaming endpoint – streams Claude tokens to frontend in real-time."""
    import urllib.request, ssl, http.client

    question = request.question.strip()
    if not question:
        raise HTTPException(400, "Bitte stelle eine Frage")

    if not ANTHROPIC_API_KEY:
        raise HTTPException(501, "Claude API nicht konfiguriert")

    db = get_db()
    try:
        # Search KB for context
        results = search_knowledge_base(db, question)
        context = build_context(results) if results else ""
    finally:
        db.close()

    system_prompt = """Du bist BEATRIX, die Strategic Intelligence Suite von FehrAdvice & Partners AG.
Du bist spezialisiert auf das Evidence-Based Framework (EBF), Behavioral Economics, das Behavioral Competence Model (BCM) und Decision Architecture.

Dir steht vorhandenes Wissen aus der BEATRIX Knowledge Base zur Verfügung.

Deine Aufgabe:
- Beantworte Fragen basierend auf dem bereitgestellten Kontext
- Antworte präzise, wissenschaftlich fundiert und praxisorientiert
- Antworte auf Deutsch, es sei denn die Frage ist auf Englisch
- Strukturiere deine Antwort klar mit Markdown-Überschriften und Absätzen

Stil: Professionell, klar, auf den Punkt. Wie ein Senior Berater bei FehrAdvice."""

    user_message = f"""Kontext aus der BEATRIX Knowledge Base:

{context}

---

{question}"""

    async def event_generator():
        """Generator that streams Claude API response as SSE events."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4000,
            "stream": True,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}]
        }).encode()

        full_text = []
        try:
            # Use http.client for streaming (urllib doesn't support chunked reading well)
            conn = http.client.HTTPSConnection("api.anthropic.com", context=ctx)
            conn.request("POST", "/v1/messages", body=payload, headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
                "User-Agent": "BEATRIXLab/3.11"
            })
            resp = conn.getresponse()

            if resp.status != 200:
                error_body = resp.read().decode()
                logger.error(f"Claude stream error: {resp.status} {error_body[:200]}")
                yield f"data: {json.dumps({'type': 'error', 'text': 'Claude API Fehler'})}\n\n"
                return

            buffer = ""
            while True:
                chunk = resp.read(1024)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", errors="replace")

                # Process complete SSE events from buffer
                while "\n\n" in buffer:
                    event_str, buffer = buffer.split("\n\n", 1)
                    for line in event_str.split("\n"):
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str.strip() == "[DONE]":
                                continue
                            try:
                                event = json.loads(data_str)
                                event_type = event.get("type", "")

                                if event_type == "content_block_delta":
                                    delta = event.get("delta", {})
                                    if delta.get("type") == "text_delta":
                                        text_chunk = delta.get("text", "")
                                        full_text.append(text_chunk)
                                        yield f"data: {json.dumps({'type': 'token', 'text': text_chunk})}\n\n"

                                elif event_type == "message_stop":
                                    yield f"data: {json.dumps({'type': 'done', 'text': ''})}\n\n"

                            except json.JSONDecodeError:
                                pass

            conn.close()

            # Store complete answer in DB
            complete_text = "".join(full_text)
            if complete_text:
                db2 = get_db()
                try:
                    assistant_msg = ChatMessage(user_email=user["sub"], role="assistant", content=complete_text, sources=[])
                    db2.add(assistant_msg)
                    db2.commit()
                except Exception:
                    pass
                finally:
                    db2.close()

            # Final done event
            yield f"data: {json.dumps({'type': 'done', 'text': ''})}\n\n"

        except Exception as e:
            logger.error(f"Stream error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'text': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )

@app.post("/api/chat")
async def chat(request: ChatRequest, user=Depends(require_auth)):
    question = request.question.strip()
    if not question:
        raise HTTPException(400, "Bitte stelle eine Frage")
    if len(question) > 5000:
        raise HTTPException(400, "Frage zu lang (max 5000 Zeichen)")

    db = get_db()
    try:
        # Store user message
        user_msg = ChatMessage(user_email=user["sub"], role="user", content=question)
        db.add(user_msg); db.commit()

        # === PATH DECISION: Search KB for existing EBF answers ===
        results = search_knowledge_base(db, question)
        top_score = results[0][0] if results else 0
        ebf_results = [(s, d) for s, d in results if d.source_type == "ebf_answer" or (d.tags and "ebf-answer" in d.tags)]
        ebf_score = ebf_results[0][0] if ebf_results else 0

        # Decision: Use fast path only if we have a strong EBF answer match
        # or if there's a very strong general match AND an EBF answer exists at all
        use_fast_path = (ebf_score >= FAST_PATH_THRESHOLD) or (top_score >= FAST_PATH_THRESHOLD * 3 and ebf_score > 0)

        # If fast path uses general docs (not EBF answers), prioritize EBF answers in context
        if use_fast_path and ebf_results:
            # Put EBF answers first in results
            non_ebf = [(s, d) for s, d in results if d not in [d2 for _, d2 in ebf_results]]
            results = ebf_results + non_ebf

        logger.info(f"Chat: q='{question[:50]}' | top={top_score} | ebf={ebf_score} | fast={use_fast_path}")

        # === FAST PATH: Good KB match exists → Claude API with context (3 sec) ===
        if use_fast_path and ANTHROPIC_API_KEY:
            context = build_context(results)
            sources = [{"title": doc.title, "id": doc.id, "type": doc.source_type, "category": doc.category} for _, doc in results[:5]]
            try:
                answer = fast_path_answer(question, context, sources)
                assistant_msg = ChatMessage(user_email=user["sub"], role="assistant", content=answer, sources=sources)
                db.add(assistant_msg); db.commit()
                logger.info(f"FAST PATH answer for: {question[:50]}")
                return {
                    "status": "done",
                    "answer": answer,
                    "sources": sources,
                    "path": "fast",
                    "knowledge_score": top_score
                }
            except Exception as e:
                logger.warning(f"Fast path failed, falling through to deep path: {e}")

        # === DEEP PATH: No good match → GitHub Claude Code (4-5 min) ===
        if not GH_TOKEN:
            raise HTTPException(501, "Kein ausreichendes Wissen vorhanden und GitHub-Integration nicht konfiguriert")

        gh = create_github_issue(question, user["sub"])
        logger.info(f"DEEP PATH: GitHub Issue #{gh['issue_number']} for: {question[:50]}")

        return {
            "status": "processing",
            "issue_number": gh["issue_number"],
            "issue_url": gh["html_url"],
            "path": "deep",
            "knowledge_score": top_score,
            "message": "Neue Frage! BEATRIX erarbeitet die Antwort mit dem Evidence-Based Framework..."
        }
    except HTTPException: raise
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(500, f"Konnte Frage nicht verarbeiten: {str(e)}")
    finally: db.close()

@app.get("/api/chat/poll/{issue_number}")
async def chat_poll(issue_number: int, user=Depends(require_auth)):
    """Poll for Claude Code's answer on a GitHub Issue. Stores answer in KB when done."""
    try:
        result = poll_github_answer(issue_number)
        if result["status"] == "done":
            db = get_db()
            try:
                # 1. Store in chat history
                assistant_msg = ChatMessage(
                    user_email=user["sub"], role="assistant",
                    content=result["answer"],
                    sources=[{"type": "github", "url": result.get("comment_url", "")}]
                )
                db.add(assistant_msg); db.commit()

                # 2. Store in Knowledge Base for future fast path!
                # Get the original question from the issue
                import urllib.request, ssl
                ctx2 = ssl.create_default_context(); ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(
                    f"https://api.github.com/repos/{GH_CONTEXT_REPO}/issues/{issue_number}",
                    headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"})
                issue = json.loads(urllib.request.urlopen(req, context=ctx2).read())
                # Extract question from issue body (after @claude)
                body = issue.get("body", "")
                q_parts = body.split("@claude", 1)
                original_question = q_parts[1].strip() if len(q_parts) > 1 else issue.get("title", "").replace("BEATRIX: ", "")

                store_ebf_answer(db, original_question, result["answer"], result.get("comment_url", ""))
                logger.info(f"EBF answer cached from Issue #{issue_number}")
            finally: db.close()
        return result
    except Exception as e:
        logger.error(f"Poll error: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/chat/history")
async def chat_history(limit: int = 50, user=Depends(require_auth)):
    db = get_db()
    try:
        msgs = db.query(ChatMessage).filter(ChatMessage.user_email == user["sub"]).order_by(ChatMessage.created_at.desc()).limit(limit).all()
        return [{"id": m.id, "role": m.role, "content": m.content, "sources": m.sources, "created_at": m.created_at.isoformat()} for m in reversed(msgs)]
    finally: db.close()

@app.delete("/api/chat/history")
async def clear_chat_history(user=Depends(require_auth)):
    db = get_db()
    try:
        db.query(ChatMessage).filter(ChatMessage.user_email == user["sub"]).delete()
        db.commit()
        return {"message": "Chat-Verlauf gelöscht"}
    finally: db.close()

@app.post("/api/upload", response_model=DocumentResponse)
async def upload_file(file: UploadFile = File(...), database: str = Form("knowledge_base"), user=Depends(require_auth)):
    ext = file.filename.split(".")[-1].lower() if file.filename else ""
    if ext not in {"pdf", "txt", "md", "docx", "csv", "json"}: raise HTTPException(400, f"Dateityp .{ext} nicht unterstuetzt")
    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE: raise HTTPException(400, "Datei zu gross (max 50 MB)")
    # Duplicate check via SHA256 hash
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    db = get_db()
    try:
        existing = db.query(Document).filter(Document.content_hash == content_hash).first()
        if existing:
            raise HTTPException(409, f"Duplikat: Diese Datei wurde bereits hochgeladen als \"{existing.title}\" ({existing.created_at.strftime('%d.%m.%Y %H:%M')})")
        file_id = str(uuid.uuid4()); file_path = UPLOAD_DIR / f"{file_id}.{ext}"
        with open(file_path, "wb") as f: f.write(content_bytes)
        text_content = extract_text(str(file_path), ext)
        gh_result = push_to_github(file.filename, content_bytes)
        github_url = gh_result.get("url", None); gh_status = "indexed+github" if github_url else "indexed"
        doc = Document(id=file_id, title=file.filename or "Unnamed", content=text_content, source_type="file", file_type=ext, file_path=str(file_path), file_size=len(content_bytes), database_target=database, status=gh_status, github_url=github_url, uploaded_by=user.get("sub"), content_hash=content_hash, doc_metadata={"original_filename": file.filename, "content_length": len(text_content), "github": gh_result})
        db.add(doc); db.commit(); db.refresh(doc)
        return DocumentResponse(id=doc.id, title=doc.title, source_type=doc.source_type, file_type=doc.file_type, database_target=doc.database_target, status=doc.status, created_at=doc.created_at.isoformat(), github_url=doc.github_url)
    except HTTPException: raise
    except Exception as e: db.rollback(); raise HTTPException(500, f"Datenbankfehler: {e}")
    finally: db.close()

@app.post("/api/text", response_model=DocumentResponse)
async def upload_text(request: TextUploadRequest, user=Depends(require_auth)):
    if not request.content.strip(): raise HTTPException(400, "Inhalt darf nicht leer sein")
    # Duplicate check via SHA256 hash of content
    content_hash = hashlib.sha256(request.content.encode("utf-8")).hexdigest()
    db = get_db()
    try:
        existing = db.query(Document).filter(Document.content_hash == content_hash).first()
        if existing:
            raise HTTPException(409, f"Duplikat: Dieser Text wurde bereits gespeichert als \"{existing.title}\" ({existing.created_at.strftime('%d.%m.%Y %H:%M')})")
        filename = f"{request.title.replace(' ', '_').replace('/', '-')}.txt"
        gh_result = push_to_github(filename, request.content.encode("utf-8")) or {}
        github_url = gh_result.get("url", None) if isinstance(gh_result, dict) else None
        doc = Document(title=request.title, content=request.content, source_type="text", database_target=request.database or "knowledge_base", category=request.category, language=request.language, tags=request.tags, status="indexed+github" if github_url else "indexed", github_url=github_url, uploaded_by=user.get("sub"), content_hash=content_hash, doc_metadata={"content_length": len(request.content), "github": gh_result or {}})
        db.add(doc); db.commit(); db.refresh(doc)
        # Auto-embed for vector search
        embed_document(db, doc.id)
        return DocumentResponse(id=doc.id, title=doc.title, source_type=doc.source_type, file_type=None, database_target=doc.database_target, status=doc.status, created_at=doc.created_at.isoformat(), github_url=doc.github_url)
    except HTTPException: raise
    except Exception as e: db.rollback(); raise HTTPException(500, f"Datenbankfehler: {e}")
    finally: db.close()

@app.get("/api/documents")
async def list_documents(database: Optional[str] = None, limit: int = 50, user=Depends(require_auth)):
    db = get_db()
    try:
        query = db.query(Document).order_by(Document.created_at.desc())
        if database: query = query.filter(Document.database_target == database)
        return [DocumentResponse(id=d.id, title=d.title, source_type=d.source_type, file_type=d.file_type, database_target=d.database_target, status=d.status, created_at=d.created_at.isoformat(), github_url=d.github_url) for d in query.limit(limit).all()]
    finally: db.close()

@app.delete("/api/documents/{doc_id}")
async def delete_document(doc_id: str, user=Depends(require_auth)):
    db = get_db()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc: raise HTTPException(404, "Nicht gefunden")
        if doc.file_path and os.path.exists(doc.file_path): os.remove(doc.file_path)
        db.delete(doc); db.commit()
        return {"message": f"Geloescht: {doc.title}"}
    finally: db.close()

# ========== STARTUP: Embed existing documents ==========
@app.on_event("startup")
async def startup_embed():
    """On startup, embed any documents that don't have embeddings yet."""
    if not VOYAGE_API_KEY:
        logger.info("No VOYAGE_API_KEY set — vector search disabled, using keyword fallback")
        return
    logger.info("Starting background embedding of existing documents...")
    try:
        db = get_db()
        count = embed_all_documents(db)
        db.close()
        logger.info(f"Startup embedding complete: {count} documents embedded")
    except Exception as e:
        logger.warning(f"Startup embedding error (non-critical): {e}")

# ========== ADMIN: Embedding management ==========
@app.get("/api/admin/embedding-stats")
async def embedding_stats(user=Depends(require_auth)):
    from sqlalchemy import text as sql_text
    db = get_db()
    try:
        total = db.query(Document).filter(Document.content.isnot(None)).count()
        try:
            embedded = db.execute(sql_text("SELECT COUNT(*) FROM documents WHERE embedding IS NOT NULL")).scalar()
        except:
            db.rollback()
            try:
                embedded = db.execute(sql_text("SELECT COUNT(*) FROM documents WHERE embedding_json IS NOT NULL AND embedding_json != ''")).scalar()
            except:
                db.rollback()
                embedded = 0
        return {
            "total_documents": total,
            "embedded": embedded,
            "not_embedded": total - embedded,
            "vector_search_enabled": bool(VOYAGE_API_KEY),
            "voyage_model": VOYAGE_MODEL
        }
    finally: db.close()

@app.post("/api/admin/embed-all")
async def admin_embed_all(user=Depends(require_auth)):
    """Admin endpoint: Trigger embedding of all un-embedded documents."""
    db = get_db()
    try:
        u = db.query(User).filter(User.email == user["sub"]).first()
        if not u or not u.is_admin:
            raise HTTPException(403, "Nur Admins")
        if not VOYAGE_API_KEY:
            raise HTTPException(400, "VOYAGE_API_KEY nicht konfiguriert")
        count = embed_all_documents(db)
        return {"message": f"{count} Dokumente embedded", "embedded": count}
    finally: db.close()

# ── Leads API ────────────────────────────────────
# ══════════════════════════════════════════════════════
# ── CRM API ──────────────────────────────────────────
# ══════════════════════════════════════════════════════

CRM_STAGES = ['prospect', 'qualified', 'proposal', 'negotiation', 'won', 'active', 'dormant', 'churned', 'lost']
CRM_STAGE_PROB = {'prospect': 10, 'qualified': 25, 'proposal': 50, 'negotiation': 75, 'won': 100, 'active': 100, 'dormant': 5, 'churned': 0, 'lost': 0, 'closed_won': 100}

# ── Companies ──
@app.get("/api/crm/companies")
async def crm_get_companies(user=Depends(require_auth)):
    db = get_db()
    try:
        rows = db.execute(text("SELECT * FROM crm_companies ORDER BY updated_at DESC")).fetchall()
        return [dict(r._mapping) for r in rows]
    except: return []
    finally: db.close()

# GitHub-enriched companies – merges customer-registry.yaml with CRM data
_github_companies_cache = {"data": None, "ts": 0}

@app.get("/api/crm/companies/enriched")
async def crm_get_companies_enriched(user=Depends(require_auth)):
    """Fetch companies from GitHub customer-registry.yaml + customer profiles, merge with CRM DB."""
    import yaml, time as _time, urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    db = get_db()
    try:
        # Cache GitHub data for 5 minutes
        now = _time.time()
        if _github_companies_cache["data"] and now - _github_companies_cache["ts"] < 300:
            github_customers = _github_companies_cache["data"]
        else:
            github_customers = []
            contacts_by_customer = {}
            try:
                # Fetch customer-registry.yaml
                gh_headers = {"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3.raw"}
                url = f"https://api.github.com/repos/{GH_REPO}/contents/data/customer-registry.yaml"
                req = urllib.request.Request(url, headers=gh_headers)
                content = urllib.request.urlopen(req, context=ctx, timeout=10).read().decode()
                registry = yaml.safe_load(content)
                github_customers = registry.get("customers", [])

                # Fetch customer-contacts.yaml for contact data
                try:
                    url2 = f"https://api.github.com/repos/{GH_REPO}/contents/data/customer-contacts.yaml"
                    req2 = urllib.request.Request(url2, headers=gh_headers)
                    contacts_content = urllib.request.urlopen(req2, context=ctx, timeout=10).read().decode()
                    contacts_data = yaml.safe_load(contacts_content)
                    for c in contacts_data.get("customers", []):
                        cid = c.get("customer_id", "")
                        contacts_by_customer[cid] = c
                except Exception as ce:
                    logger.warning(f"Contacts fetch: {ce}")

                # Fetch lead-database.yaml for full company list
                try:
                    url3 = f"https://api.github.com/repos/{GH_REPO}/contents/data/sales/lead-database.yaml"
                    req3 = urllib.request.Request(url3, headers=gh_headers)
                    leads_content = urllib.request.urlopen(req3, context=ctx, timeout=30).read().decode()
                    leads_data = yaml.safe_load(leads_content)
                    leads_list = leads_data.get("leads", [])
                    
                    # Build set of existing customer codes
                    existing_codes = {c.get("code","").upper() for c in github_customers}
                    
                    # Add companies from leads that aren't in customer-registry
                    for lead in leads_list:
                        co = lead.get("company", {})
                        if isinstance(co, str):
                            co = {"name": co, "short_name": co}
                        short = co.get("short_name", "")
                        if not short or short.upper() in existing_codes:
                            continue
                        existing_codes.add(short.upper())
                        
                        # Extract contacts from lead
                        lead_contacts = lead.get("contacts", [])
                        contact_count = len(lead_contacts) if isinstance(lead_contacts, list) else 0
                        
                        # Extract EBF/context data
                        ebf = lead.get("ebf_integration", {})
                        
                        github_customers.append({
                            "id": lead.get("id", ""),
                            "code": short,
                            "name": co.get("name", short),
                            "short_name": short,
                            "type": "lead",
                            "industry": lead.get("industry", ""),
                            "country": (lead.get("headquarters", {}) or {}).get("country", "") if isinstance(lead.get("headquarters"), dict) else "",
                            "status": lead.get("stage", ""),
                            "profile_path": None,
                            "context_path": None,
                            "notes": lead.get("notes", ""),
                            "lead_id": lead.get("id", ""),
                            "segment": lead.get("segment", ""),
                            "fit_score": lead.get("fit_score", 0),
                            "engagement_score": lead.get("engagement_score", 0),
                            "source": lead.get("source", ""),
                            "hot_lead": lead.get("hot_lead", False),
                            "priority": lead.get("priority", ""),
                            "next_action": lead.get("next_action", ""),
                            "next_action_date": lead.get("next_action_date", ""),
                            "tags": lead.get("tags", []),
                            "website": co.get("website", ""),
                            "linkedin": co.get("linkedin", ""),
                            "employee_count": lead.get("employee_count"),
                            "revenue_eur": lead.get("revenue_eur"),
                            "ebf_context_vectors": ebf.get("context_vectors") if isinstance(ebf, dict) else None,
                            "ebf_applicable_models": ebf.get("applicable_models") if isinstance(ebf, dict) else None,
                            "_lead_contacts": lead_contacts,
                            "_contact_count": contact_count,
                        })
                    logger.info(f"Lead-database merged: {len(leads_list)} leads, now {len(github_customers)} total companies")
                except Exception as le:
                    logger.warning(f"Lead-database fetch: {le}")

                # Enrich registry customers with contacts
                for cust in github_customers:
                    code = cust.get("code", "")
                    if code in contacts_by_customer:
                        cust["_contacts"] = contacts_by_customer[code]

                _github_companies_cache["data"] = github_customers
                _github_companies_cache["ts"] = now
                logger.info(f"GitHub customer registry loaded: {len(github_customers)} customers")
            except Exception as e:
                logger.error(f"GitHub customer fetch error: {e}")

        # Get CRM DB companies + deals for merge
        db_companies = {}
        try:
            rows = db.execute(text("SELECT * FROM crm_companies")).fetchall()
            for r in rows:
                m = dict(r._mapping)
                db_companies[m.get("name", "")] = m
                db_companies[m.get("domain", "")] = m
        except: pass

        # Get deal stats per company
        deal_stats = {}
        try:
            deals = db.execute(text("""SELECT d.company_id, d.company_name, d.stage, d.value, c.name as cname
                FROM crm_deals d LEFT JOIN crm_companies c ON d.company_id = c.id""")).fetchall()
            for d in deals:
                key = d.cname or d.company_name or d.company_id
                if not key: continue
                if key not in deal_stats:
                    deal_stats[key] = {"leads": 0, "active": 0, "won": 0, "pipeline": 0}
                deal_stats[key]["leads"] += 1
                if d.stage in ('Prospect','Qualified','Proposal','Negotiation','Active'):
                    deal_stats[key]["active"] += 1
                if d.stage == 'Won':
                    deal_stats[key]["won"] += 1
                deal_stats[key]["pipeline"] += float(d.value or 0)
        except: pass

        # Get contact counts
        contact_counts = {}
        try:
            contacts = db.execute(text("SELECT company_id, COUNT(*) as cnt FROM crm_contacts GROUP BY company_id")).fetchall()
            for c in contacts:
                contact_counts[c.company_id] = c.cnt
        except: pass

        # Get customer folders from GitHub
        customer_folders = _get_customer_folders()

        # Merge: GitHub as primary, enriched with CRM stats
        result = []
        for cust in github_customers:
            code = cust.get("code", "")
            name = cust.get("name", "")
            short = cust.get("short_name", code)
            db_match = db_companies.get(name) or db_companies.get(code) or {}
            ds = deal_stats.get(name) or deal_stats.get(short) or deal_stats.get(code) or {}
            cc = cust.get("_contacts", {})

            result.append({
                "id": cust.get("id", ""),
                "code": code,
                "name": name,
                "short_name": short,
                "type": cust.get("type", ""),
                "industry": cust.get("industry", ""),
                "country": cust.get("country", ""),
                "status": cust.get("status", ""),
                "profile_path": cust.get("profile_path"),
                "context_path": cust.get("context_path"),
                "notes": cust.get("notes", ""),
                "has_profile": bool(cust.get("profile_path")),
                "has_context": bool(cust.get("context_path")),
                "has_customer_folder": code.lower() in [d.lower() for d in customer_folders],
                # CRM stats from DB
                "leads": ds.get("leads", 0),
                "active_leads": ds.get("active", 0),
                "won": ds.get("won", 0),
                "pipeline": ds.get("pipeline", 0),
                "db_contacts": contact_counts.get(db_match.get("id"), 0),
                # Contact info from GitHub customer-contacts
                "fa_owner": cc.get("fa_owner", "") or cust.get("_contacts", {}).get("fa_owner", ""),
                "relationship_status": cc.get("relationship_status", "") or cust.get("_contacts", {}).get("relationship_status", ""),
                "contact_persons": len(cc.get("contacts", [])) if isinstance(cc.get("contacts"), list) else cust.get("_contact_count", 0),
                # Lead-enriched fields (from lead-database.yaml)
                "lead_id": cust.get("lead_id", ""),
                "segment": cust.get("segment", ""),
                "fit_score": cust.get("fit_score", 0),
                "engagement_score": cust.get("engagement_score", 0),
                "source": cust.get("source", ""),
                "hot_lead": cust.get("hot_lead", False),
                "priority": cust.get("priority", ""),
                "next_action": cust.get("next_action", ""),
                "next_action_date": cust.get("next_action_date", ""),
                "tags": cust.get("tags", []),
                "website": cust.get("website", ""),
                "linkedin": cust.get("linkedin", ""),
                "employee_count": cust.get("employee_count"),
                "revenue_eur": cust.get("revenue_eur"),
                "ebf_context_vectors": cust.get("ebf_context_vectors"),
                "ebf_applicable_models": cust.get("ebf_applicable_models"),
            })

        # ── Group by parent company ──
        # Step 1: Identify parent codes (strategic/context type, or unique root codes)
        all_codes = [r["code"] for r in result]
        parent_candidates = set()
        for r in result:
            if r["type"] in ("strategic", "context"):
                parent_candidates.add(r["code"])

        # Step 2: For each company, find parent by prefix matching
        for r in result:
            r["parent_code"] = None
            if r["code"] in parent_candidates:
                r["parent_code"] = r["code"]  # is itself a parent
                continue
            # Check if code starts with a known parent code
            for pc in sorted(parent_candidates, key=len, reverse=True):
                if r["code"].upper().startswith(pc.upper()) and r["code"] != pc:
                    r["parent_code"] = pc
                    break

        # Step 3: Detect additional groups by name prefix (e.g. "DS Studio" entries)
        ungrouped = [r for r in result if not r["parent_code"]]
        from collections import Counter
        # Find names that share a common prefix (first word)
        first_words = Counter()
        for r in ungrouped:
            fw = r["name"].split()[0] if r["name"] else ""
            if len(fw) > 2:
                first_words[fw] += 1
        # Group if 2+ entries share same first word
        multi_groups = {fw for fw, cnt in first_words.items() if cnt >= 2}
        for r in result:
            if not r["parent_code"] and r["name"]:
                fw = r["name"].split()[0]
                if fw in multi_groups:
                    # Find or create parent: prefer strategic, else first entry
                    group_members = [x for x in result if x["name"].split()[0] == fw]
                    parent = next((x for x in group_members if x["type"] in ("strategic","context")), group_members[0])
                    r["parent_code"] = parent["code"]

        # Step 4: Entries without a group are their own parent
        for r in result:
            if not r["parent_code"]:
                r["parent_code"] = r["code"]

        # Build grouped output
        groups = {}
        for r in result:
            pc = r["parent_code"]
            if pc not in groups:
                groups[pc] = {"parent": None, "children": []}
            if r["code"] == pc:
                groups[pc]["parent"] = r
            else:
                groups[pc]["children"].append(r)

        # For groups without an explicit parent, promote first child
        for pc, g in groups.items():
            if not g["parent"] and g["children"]:
                g["parent"] = g["children"].pop(0)

        # Build final sorted list
        grouped_result = []
        for pc in sorted(groups.keys(), key=lambda k: groups[k]["parent"]["name"] if groups[k]["parent"] else ""):
            g = groups[pc]
            if not g["parent"]:
                continue
            parent = g["parent"]
            children = sorted(g["children"], key=lambda x: x["name"])
            # Aggregate stats
            parent["child_count"] = len(children)
            parent["total_leads"] = parent.get("leads", 0) + sum(c.get("leads", 0) for c in children)
            parent["total_contacts"] = parent.get("contact_persons", 0) + sum(c.get("contact_persons", 0) for c in children)
            parent["children"] = children
            grouped_result.append(parent)

        return grouped_result
    except Exception as e:
        logger.error(f"Enriched companies error: {e}")
        return []
    finally: db.close()

# ── PROJECT ENDPOINTS ──

@app.get("/api/projects")
async def get_projects(user=Depends(require_auth)):
    """List all projects from GitHub data/projects/*/project.yaml"""
    import urllib.request, ssl, yaml
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        url = f"https://api.github.com/repos/{GH_REPO}/contents/data/projects"
        req = urllib.request.Request(url, headers={"Authorization": f"token {GH_TOKEN}", "User-Agent": "BEATRIXLab"})
        items = json.loads(urllib.request.urlopen(req, context=ctx, timeout=15).read())
        projects = []
        for item in items:
            if item["type"] != "dir":
                continue
            # Fetch project.yaml
            try:
                pyaml_url = f"https://api.github.com/repos/{GH_REPO}/contents/data/projects/{item['name']}/project.yaml"
                req2 = urllib.request.Request(pyaml_url, headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3.raw", "User-Agent": "BEATRIXLab"})
                content = urllib.request.urlopen(req2, context=ctx, timeout=15).read().decode()
                data = yaml.safe_load(content) or {}
                meta = data.get("metadata", {})
                client = data.get("client", {})
                project = data.get("project", {})
                timeline = data.get("timeline", {})
                team = data.get("team", {})
                # Handle timeline as list (milestone-style) vs dict
                if isinstance(timeline, list):
                    tl_start = timeline[0].get("date", "") if timeline else ""
                    tl_end = timeline[-1].get("date", "") if timeline else ""
                    tl_budget = None
                    tl_billing = ""
                else:
                    tl_start = timeline.get("start_date", "")
                    tl_end = timeline.get("end_date", "")
                    tl_budget = timeline.get("budget_chf", timeline.get("budget_eur"))
                    tl_billing = timeline.get("billing_type", "")
                # Handle team as dict or missing
                if not isinstance(team, dict):
                    team = {}
                # Extract fa_owner from various locations
                fa_owner = team.get("fa_owner", "")
                if not fa_owner and isinstance(team.get("fehradvice_team"), list):
                    for member in team["fehradvice_team"]:
                        if isinstance(member, dict) and member.get("role", "").lower() in ("lead", "owner", "projektleiter"):
                            fa_owner = member.get("name", member.get("code", ""))
                            break
                # Extract name from multiple possible fields
                prj_name = project.get("name") or meta.get("name") or item["name"]
                # Extract customer name
                cust_name = client.get("name") or client.get("short_name") or meta.get("customer", "")
                projects.append({
                    "project_id": meta.get("project_id", ""),
                    "project_code": meta.get("project_code", meta.get("short_code", item["name"])),
                    "slug": item["name"],
                    "name": prj_name,
                    "type": project.get("type", ""),
                    "status": meta.get("status", "planning").lower(),
                    "customer_code": client.get("customer_code", client.get("short_name", "")),
                    "customer_name": cust_name,
                    "start_date": tl_start,
                    "end_date": tl_end,
                    "budget_chf": tl_budget,
                    "billing_type": tl_billing,
                    "fa_owner": fa_owner,
                    "fa_team": team.get("fa_team", []),
                    "created": meta.get("created", ""),
                    "last_updated": meta.get("last_updated", ""),
                    "github_path": f"data/projects/{item['name']}/project.yaml"
                })
            except Exception as e2:
                logger.warning(f"Could not read project {item['name']}: {e2}")
                continue
        projects.sort(key=lambda x: (0 if x["status"] in ("active","aktiv") else 1 if x["status"]=="planning" else 2, x.get("start_date","") or ""))
        return projects
    except Exception as e:
        logger.error(f"Get projects error: {e}")
        return []

@app.post("/api/projects")
async def create_project(request: Request, user=Depends(require_auth)):
    """Create a new project: push project.yaml to GitHub"""
    try:
        import urllib.request, ssl, yaml
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        body = await request.json()

        customer_code = body.get("customer_code", "").strip()
        name = body.get("name", "").strip()
        if not customer_code or not name:
            return JSONResponse({"error": "customer_code and name required"}, status_code=400)

        slug = f"{customer_code}-{name}".lower()
        slug = "".join(c if c.isalnum() or c == '-' else '-' for c in slug)
        slug = "-".join(part for part in slug.split("-") if part)[:60]
        project_id = f"PRJ-{slug.upper()[:30]}"
        today = datetime.utcnow().strftime("%Y-%m-%d")

        # Check if project already exists
        check_url = f"https://api.github.com/repos/{GH_REPO}/contents/data/projects/{slug}"
        try:
            check_req = urllib.request.Request(check_url, headers={"Authorization": f"token {GH_TOKEN}", "User-Agent": "BEATRIXLab"})
            urllib.request.urlopen(check_req, context=ctx, timeout=10)
            return JSONResponse({"error": f"Projekt '{slug}' existiert bereits auf GitHub"}, status_code=409)
        except urllib.error.HTTPError as he:
            if he.code != 404:
                logger.warning(f"GitHub check error: {he}")
        except:
            pass

        # Build project.yaml
        project_yaml = {
            "metadata": {
                "project_id": project_id,
                "project_code": slug,
                "status": "planning",
                "created": today,
                "created_by": user.get("sub", user.get("email","")),
                "last_updated": today,
                "version": "1.0"
            },
            "client": {
                "customer_code": customer_code,
                "name": body.get("customer_name", customer_code),
            },
            "project": {
                "name": name,
                "type": body.get("type", "beratung"),
                "description": body.get("description", ""),
                "objectives": [],
            },
            "timeline": {
                "start_date": body.get("start_date", today),
                "end_date": body.get("end_date", ""),
                "budget_chf": body.get("budget_chf"),
                "billing_type": body.get("billing_type", "fixed"),
            },
            "team": {
                "fa_owner": body.get("fa_owner", "GF"),
                "fa_team": body.get("fa_team", []),
                "client_contacts": [],
            },
            "ebf_integration": {
                "bcm_models": [],
                "psi_dimensions": [],
                "behavioral_objectives": [],
            },
            "deliverables": [],
            "resources": [],
            "changelog": [{
                "date": today,
                "author": user.get("sub", user.get("email","")),
                "action": "Projekt eröffnet via BEATRIX"
            }]
        }

        # Enrich client name from companies cache
        try:
            reg_url = f"https://api.github.com/repos/{GH_REPO}/contents/data/sales/customer-registry.yaml"
            req = urllib.request.Request(reg_url, headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3.raw", "User-Agent": "BEATRIXLab"})
            reg_data = yaml.safe_load(urllib.request.urlopen(req, context=ctx, timeout=15).read().decode()) or {}
            for cust in reg_data.get("customers", []):
                if cust.get("code", "").upper() == customer_code.upper():
                    project_yaml["client"]["name"] = cust.get("name", customer_code)
                    project_yaml["client"]["industry"] = cust.get("industry", "")
                    project_yaml["client"]["country"] = cust.get("country", "")
                    break
        except Exception as enrich_err:
            logger.warning(f"Could not enrich client: {enrich_err}")

        # Push to GitHub
        yaml_content = yaml.dump(project_yaml, default_flow_style=False, allow_unicode=True, sort_keys=False)
        file_path = f"data/projects/{slug}/project.yaml"
        put_url = f"https://api.github.com/repos/{GH_REPO}/contents/{file_path}"
        put_data = json.dumps({
            "message": f"Projekt eröffnet: {name} ({customer_code})",
            "content": base64.b64encode(yaml_content.encode()).decode(),
            "branch": "main"
        }).encode()
        req = urllib.request.Request(put_url, data=put_data, method="PUT",
            headers={"Authorization": f"token {GH_TOKEN}", "Content-Type": "application/json", "User-Agent": "BEATRIXLab"})
        result = json.loads(urllib.request.urlopen(req, context=ctx, timeout=15).read())
        logger.info(f"Project created: {slug} by {user['email']}")
        return {"ok": True, "project_id": project_id, "slug": slug, "github_path": file_path, "sha": result.get("content", {}).get("sha", "")}
    except Exception as e:
        logger.error(f"Create project error: {e}")
        import traceback; traceback.print_exc()
        return JSONResponse({"error": f"Fehler: {str(e)}"}, status_code=500)

# Cache customer folders list
_customer_folders_cache = {"data": [], "ts": 0}
def _get_customer_folders():
    import time as _time, urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    now = _time.time()
    if _customer_folders_cache["data"] and now - _customer_folders_cache["ts"] < 300:
        return _customer_folders_cache["data"]
    try:
        gh_headers = {"Authorization": f"token {GH_TOKEN}"}
        url = f"https://api.github.com/repos/{GH_REPO}/contents/data/customers"
        req = urllib.request.Request(url, headers=gh_headers)
        items = json.loads(urllib.request.urlopen(req, context=ctx, timeout=10).read())
        folders = [i["name"] for i in items if i["type"] == "dir"]
        _customer_folders_cache["data"] = folders
        _customer_folders_cache["ts"] = now
        return folders
    except:
        return _customer_folders_cache["data"]

@app.post("/api/crm/companies")
async def crm_create_company(request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        data = await request.json()
        cid = str(uuid.uuid4())[:8]
        db.execute(text("""INSERT INTO crm_companies (id, name, domain, industry, size, website, address, notes, created_by)
            VALUES (:id, :name, :domain, :industry, :size, :website, :address, :notes, :cb)"""),
            {"id": cid, "name": data.get("name",""), "domain": data.get("domain",""),
             "industry": data.get("industry",""), "size": data.get("size",""),
             "website": data.get("website",""), "address": data.get("address",""),
             "notes": data.get("notes",""), "cb": user["sub"]})
        db.commit()
        return {"id": cid, "status": "created"}
    except Exception as e:
        db.rollback(); raise HTTPException(500, str(e))
    finally: db.close()

@app.put("/api/crm/companies/{cid}")
async def crm_update_company(cid: str, request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        data = await request.json()
        sets, params = [], {"id": cid}
        for f in ["name","domain","industry","size","website","address","notes"]:
            if f in data: sets.append(f"{f} = :{f}"); params[f] = data[f]
        if not sets: return {"status": "no changes"}
        sets.append("updated_at = CURRENT_TIMESTAMP")
        db.execute(text(f"UPDATE crm_companies SET {', '.join(sets)} WHERE id = :id"), params)
        db.commit()
        return {"status": "updated"}
    except Exception as e:
        db.rollback(); raise HTTPException(500, str(e))
    finally: db.close()

# ── Contacts ──
@app.get("/api/crm/contacts")
async def crm_get_contacts(user=Depends(require_auth), company_id: str = None):
    db = get_db()
    try:
        if company_id:
            rows = db.execute(text("SELECT * FROM crm_contacts WHERE company_id = :cid ORDER BY updated_at DESC"), {"cid": company_id}).fetchall()
        else:
            rows = db.execute(text("SELECT * FROM crm_contacts ORDER BY updated_at DESC")).fetchall()
        return [dict(r._mapping) for r in rows]
    except: return []
    finally: db.close()

@app.post("/api/crm/contacts")
async def crm_create_contact(request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        data = await request.json()
        cid = str(uuid.uuid4())[:8]
        db.execute(text("""INSERT INTO crm_contacts (id, company_id, name, email, phone, position, role_type, notes, created_by)
            VALUES (:id, :company_id, :name, :email, :phone, :position, :role_type, :notes, :cb)"""),
            {"id": cid, "company_id": data.get("company_id"), "name": data.get("name",""),
             "email": data.get("email",""), "phone": data.get("phone",""),
             "position": data.get("position",""), "role_type": data.get("role_type","kontakt"),
             "notes": data.get("notes",""), "cb": user["sub"]})
        db.commit()
        return {"id": cid, "status": "created"}
    except Exception as e:
        db.rollback(); raise HTTPException(500, str(e))
    finally: db.close()

@app.put("/api/crm/contacts/{cid}")
async def crm_update_contact(cid: str, request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        data = await request.json()
        sets, params = [], {"id": cid}
        for f in ["company_id","name","email","phone","position","role_type","psi_profile","notes"]:
            if f in data: sets.append(f"{f} = :{f}"); params[f] = data[f] if f != "psi_profile" else json.dumps(data[f])
        if not sets: return {"status": "no changes"}
        sets.append("updated_at = CURRENT_TIMESTAMP")
        db.execute(text(f"UPDATE crm_contacts SET {', '.join(sets)} WHERE id = :id"), params)
        db.commit()
        return {"status": "updated"}
    except Exception as e:
        db.rollback(); raise HTTPException(500, str(e))
    finally: db.close()

# ── Deals ──
@app.get("/api/crm/deals")
async def crm_get_deals(user=Depends(require_auth), stage: str = None):
    # CRM access check: must be @fehradvice.com with crm_access
    email = user.get("sub", "")
    crm_ok = user.get("crm_access", False)
    crm_role = user.get("crm_role", "none")
    owner_code = user.get("crm_owner_code", "")
    if not crm_ok:
        raise HTTPException(403, "Kein CRM-Zugang. Bitte Admin kontaktieren.")
    db = get_db()
    try:
        q = """SELECT d.*, c.name as company_name, ct.name as contact_name, ct.email as contact_email
               FROM crm_deals d
               LEFT JOIN crm_companies c ON d.company_id = c.id
               LEFT JOIN crm_contacts ct ON d.contact_id = ct.id"""
        params = {}
        conditions = []
        if stage:
            conditions.append("d.stage = :stage")
            params["stage"] = stage
        # Owner filtering: viewer sees only own leads, manager/admin sees all
        if crm_role not in ("admin", "manager") and not user.get("admin"):
            if owner_code:
                conditions.append("d.owner = :owner")
                params["owner"] = owner_code
            else:
                # No owner code assigned → see nothing
                return []
        if conditions:
            q += " WHERE " + " AND ".join(conditions)
        q += " ORDER BY d.updated_at DESC"
        rows = db.execute(text(q), params).fetchall()
        return [dict(r._mapping) for r in rows]
    except HTTPException: raise
    except Exception as e:
        logger.error(f"CRM deals fetch: {e}")
        return []
    finally: db.close()

@app.post("/api/crm/deals")
async def crm_create_deal(request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        data = await request.json()
        did = str(uuid.uuid4())[:8]
        stage = data.get("stage", "erstkontakt")
        prob = data.get("probability", CRM_STAGE_PROB.get(stage, 10))

        # Auto-create company if name provided but no company_id
        company_id = data.get("company_id")
        if not company_id and data.get("company_name"):
            company_id = str(uuid.uuid4())[:8]
            db.execute(text("""INSERT INTO crm_companies (id, name, created_by)
                VALUES (:id, :name, :cb)"""),
                {"id": company_id, "name": data["company_name"], "cb": user["sub"]})

        # Auto-create contact if name provided but no contact_id
        contact_id = data.get("contact_id")
        if not contact_id and data.get("contact_name"):
            contact_id = str(uuid.uuid4())[:8]
            db.execute(text("""INSERT INTO crm_contacts (id, company_id, name, email, created_by)
                VALUES (:id, :cid, :name, :email, :cb)"""),
                {"id": contact_id, "cid": company_id, "name": data["contact_name"],
                 "email": data.get("contact_email",""), "cb": user["sub"]})

        db.execute(text("""INSERT INTO crm_deals (id, company_id, contact_id, title, stage, value, probability, source, next_action, next_action_date, owner, context_id, notes, created_by)
            VALUES (:id, :company_id, :contact_id, :title, :stage, :value, :prob, :source, :next_action, :nad, :owner, :ctx, :notes, :cb)"""),
            {"id": did, "company_id": company_id, "contact_id": contact_id,
             "title": data.get("title",""), "stage": stage, "value": data.get("value",0),
             "prob": prob, "source": data.get("source",""),
             "next_action": data.get("next_action",""), "nad": data.get("next_action_date"),
             "owner": data.get("owner", user["sub"]), "ctx": data.get("context_id"),
             "notes": data.get("notes",""), "cb": user["sub"]})
        db.commit()
        logger.info(f"CRM deal created: {did} by {user['sub']}")
        return {"id": did, "company_id": company_id, "contact_id": contact_id, "status": "created"}
    except Exception as e:
        db.rollback(); logger.error(f"CRM deal create: {e}"); raise HTTPException(500, str(e))
    finally: db.close()

@app.put("/api/crm/deals/{did}")
async def crm_update_deal(did: str, request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        data = await request.json()
        sets, params = [], {"id": did}
        for f in ["company_id","contact_id","title","stage","value","probability","source","next_action","next_action_date","owner","context_id","notes","lost_reason"]:
            if f in data:
                sets.append(f"{f} = :{f}"); params[f] = data[f]
        if "stage" in data:
            if data["stage"] == "won" or data["stage"] == "lost":
                sets.append("closed_at = CURRENT_TIMESTAMP")
            if data["stage"] in CRM_STAGE_PROB and "probability" not in data:
                sets.append("probability = :auto_prob")
                params["auto_prob"] = CRM_STAGE_PROB[data["stage"]]
        if not sets: return {"status": "no changes"}
        sets.append("updated_at = CURRENT_TIMESTAMP")
        db.execute(text(f"UPDATE crm_deals SET {', '.join(sets)} WHERE id = :id"), params)
        db.commit()
        return {"status": "updated"}
    except Exception as e:
        db.rollback(); raise HTTPException(500, str(e))
    finally: db.close()

@app.delete("/api/crm/deals/{did}")
async def crm_delete_deal(did: str, user=Depends(require_auth)):
    db = get_db()
    try:
        db.execute(text("DELETE FROM crm_activities WHERE deal_id = :id"), {"id": did})
        db.execute(text("DELETE FROM crm_deals WHERE id = :id"), {"id": did})
        db.commit()
        return {"status": "deleted"}
    except Exception as e:
        db.rollback(); raise HTTPException(500, str(e))
    finally: db.close()

# ── Activities ──
@app.get("/api/crm/activities")
async def crm_get_activities(user=Depends(require_auth), deal_id: str = None, company_id: str = None):
    db = get_db()
    try:
        q = "SELECT * FROM crm_activities WHERE 1=1"
        params = {}
        if deal_id: q += " AND deal_id = :did"; params["did"] = deal_id
        if company_id: q += " AND company_id = :cid"; params["cid"] = company_id
        q += " ORDER BY created_at DESC LIMIT 100"
        rows = db.execute(text(q), params).fetchall()
        return [dict(r._mapping) for r in rows]
    except: return []
    finally: db.close()

@app.post("/api/crm/activities")
async def crm_create_activity(request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        data = await request.json()
        aid = str(uuid.uuid4())[:8]
        db.execute(text("""INSERT INTO crm_activities (id, deal_id, company_id, contact_id, type, subject, description, due_date, created_by)
            VALUES (:id, :did, :cid, :ctid, :type, :subject, :desc, :due, :cb)"""),
            {"id": aid, "did": data.get("deal_id"), "cid": data.get("company_id"),
             "ctid": data.get("contact_id"), "type": data.get("type","note"),
             "subject": data.get("subject",""), "desc": data.get("description",""),
             "due": data.get("due_date"), "cb": user["sub"]})
        db.commit()
        return {"id": aid, "status": "created"}
    except Exception as e:
        db.rollback(); raise HTTPException(500, str(e))
    finally: db.close()

# ── CRM Stats ──
@app.get("/api/crm/stats")
async def crm_stats(user=Depends(require_auth)):
    crm_ok = user.get("crm_access", False)
    crm_role = user.get("crm_role", "none")
    owner_code = user.get("crm_owner_code", "")
    if not crm_ok:
        return {"total_deals":0,"active_deals":0,"won_deals":0,"new_this_month":0,"pipeline_value":0,"total_value":0,"conversion_rate":0,"stages":{},"companies":0,"contacts":0}
    db = get_db()
    try:
        q = "SELECT stage, value, probability, created_at, closed_at FROM crm_deals"
        params = {}
        # Owner filtering for non-admin/manager
        if crm_role not in ("admin", "manager") and not user.get("admin"):
            if owner_code:
                q += " WHERE owner = :owner"
                params["owner"] = owner_code
            else:
                return {"total_deals":0,"active_deals":0,"won_deals":0,"new_this_month":0,"pipeline_value":0,"total_value":0,"conversion_rate":0,"stages":{},"companies":0,"contacts":0}
        deals = db.execute(text(q), params).fetchall()
        deals = [dict(r._mapping) for r in deals]
        active = [d for d in deals if d['stage'] not in ('won','lost')]
        won = [d for d in deals if d['stage'] == 'won']
        now = datetime.utcnow()
        this_month = [d for d in deals if d['created_at'] and d['created_at'].month == now.month and d['created_at'].year == now.year]
        pipeline_value = sum(d.get('value',0) * d.get('probability',10) / 100 for d in active)
        total_value = sum(d.get('value',0) for d in active)
        conv_rate = round(len(won) / len(deals) * 100) if deals else 0
        stages = {}
        for d in deals:
            s = d['stage']
            if s not in stages: stages[s] = {"count": 0, "value": 0}
            stages[s]["count"] += 1
            stages[s]["value"] += d.get('value',0)
        companies = db.execute(text("SELECT COUNT(*) FROM crm_companies")).scalar()
        contacts = db.execute(text("SELECT COUNT(*) FROM crm_contacts")).scalar()
        return {
            "total_deals": len(deals), "active_deals": len(active), "won_deals": len(won),
            "new_this_month": len(this_month), "pipeline_value": pipeline_value,
            "total_value": total_value, "conversion_rate": conv_rate,
            "stages": stages, "companies": companies or 0, "contacts": contacts or 0
        }
    except Exception as e:
        logger.error(f"CRM stats: {e}")
        return {"total_deals":0,"active_deals":0,"won_deals":0,"new_this_month":0,"pipeline_value":0,"total_value":0,"conversion_rate":0,"stages":{},"companies":0,"contacts":0}
    finally: db.close()

# ── Migrate old leads → CRM ──
@app.post("/api/crm/migrate-leads")
async def crm_migrate_leads(request: Request, user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Admin only")
    db = get_db()
    try:
        leads = db.execute(text("SELECT * FROM leads")).fetchall()
        migrated = 0
        stage_map = {'kontakt':'erstkontakt','qualifiziert':'discovery','proposal':'proposal','won':'won','lost':'lost'}
        for lead in leads:
            l = dict(lead._mapping)
            # Check if already migrated
            existing = db.execute(text("SELECT id FROM crm_deals WHERE notes LIKE :ref"), {"ref": f"%migrated:lead:{l['id']}%"}).fetchone()
            if existing: continue
            # Create company
            cid = str(uuid.uuid4())[:8]
            db.execute(text("INSERT INTO crm_companies (id, name, created_by) VALUES (:id, :name, :cb)"),
                {"id": cid, "name": l.get('company','Unbekannt'), "cb": l.get('created_by','system')})
            # Create contact if exists
            ctid = None
            if l.get('contact'):
                ctid = str(uuid.uuid4())[:8]
                db.execute(text("INSERT INTO crm_contacts (id, company_id, name, email, created_by) VALUES (:id, :cid, :name, :email, :cb)"),
                    {"id": ctid, "cid": cid, "name": l['contact'], "email": l.get('email',''), "cb": l.get('created_by','system')})
            # Create deal
            did = str(uuid.uuid4())[:8]
            new_stage = stage_map.get(l.get('stage','kontakt'), 'erstkontakt')
            notes = f"{l.get('notes','')}\n[migrated:lead:{l['id']}]".strip()
            db.execute(text("""INSERT INTO crm_deals (id, company_id, contact_id, title, stage, value, probability, source, notes, created_by, created_at)
                VALUES (:id, :cid, :ctid, :title, :stage, :val, :prob, :src, :notes, :cb, :ca)"""),
                {"id": did, "cid": cid, "ctid": ctid, "title": l.get('company','Deal'),
                 "stage": new_stage, "val": l.get('value',0),
                 "prob": CRM_STAGE_PROB.get(new_stage, 10), "src": l.get('source',''),
                 "notes": notes, "cb": l.get('created_by','system'),
                 "ca": l.get('created_at', datetime.utcnow())})
            migrated += 1
        db.commit()
        logger.info(f"CRM migration: {migrated} leads migrated")
        return {"migrated": migrated, "total_leads": len(leads)}
    except Exception as e:
        db.rollback(); logger.error(f"CRM migration: {e}"); raise HTTPException(500, str(e))
    finally: db.close()

# ── GitHub YAML → PostgreSQL Sync ──
@app.post("/api/crm/sync-github")
async def crm_sync_github(user=Depends(require_auth)):
    """Sync leads, customers, contacts from GitHub YAML files into PostgreSQL CRM tables"""
    import yaml, urllib.request as ureq
    db = get_db()
    try:
        gh_token = os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN", ""))
        repo = "FehrAdvice-Partners-AG/complementarity-context-framework"
        headers_gh = {"Authorization": f"token {gh_token}", "Accept": "application/vnd.github.v3.raw", "User-Agent": "BEATRIXLab/3.18"}
        ssl_ctx = __import__('ssl').create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = __import__('ssl').CERT_NONE

        def gh_read(path):
            req = ureq.Request(f"https://api.github.com/repos/{repo}/contents/{path}", headers=headers_gh)
            return ureq.urlopen(req, context=ssl_ctx).read().decode()

        stats = {"companies": 0, "contacts": 0, "deals": 0, "activities": 0, "skipped": 0}

        # ── 1. Read lead-database.yaml ──
        logger.info("CRM Sync: Reading lead-database.yaml...")
        lead_yaml = yaml.safe_load(gh_read("data/sales/lead-database.yaml"))
        leads_list = lead_yaml.get("leads", [])
        if not leads_list:
            # Try alternate structure
            leads_list = lead_yaml.get("pipeline", {}).get("leads", [])
        logger.info(f"CRM Sync: Found {len(leads_list)} leads")

        # ── 2. Read customer-registry.yaml ──
        logger.info("CRM Sync: Reading customer-registry.yaml...")
        cust_yaml = yaml.safe_load(gh_read("data/customer-registry.yaml"))
        customers_list = cust_yaml.get("customers", [])
        logger.info(f"CRM Sync: Found {len(customers_list)} customers in registry")

        # ── 3. Read person-registry.yaml ──
        logger.info("CRM Sync: Reading person-registry.yaml...")
        person_yaml = yaml.safe_load(gh_read("data/person-registry.yaml"))

        # ── 4. Sync customers from registry ──
        for cust in customers_list:
            cid = cust.get("id", cust.get("code", ""))
            if not cid: continue
            existing = db.execute(text("SELECT id FROM crm_companies WHERE id = :id"), {"id": cid}).fetchone()
            if existing:
                stats["skipped"] += 1
                continue
            db.execute(text("""INSERT INTO crm_companies (id, name, domain, industry, size, website, notes, created_by)
                VALUES (:id, :name, :domain, :industry, :size, :website, :notes, :cb)"""),
                {"id": cid, "name": cust.get("name",""), "domain": cust.get("code",""),
                 "industry": cust.get("industry",""), "size": cust.get("type",""),
                 "website": "", "notes": cust.get("notes",""), "cb": "github-sync"})
            stats["companies"] += 1

        # ── 5. Sync leads as deals + companies + contacts ──
        stage_map = {
            'PROSPECT': 'prospect', 'QUALIFIED': 'qualified', 'PROPOSAL': 'proposal',
            'NEGOTIATION': 'negotiation', 'WON': 'won', 'ACTIVE': 'active',
            'DORMANT': 'dormant', 'CHURNED': 'churned', 'LOST': 'lost', 'CLOSED_WON': 'won'
        }

        for lead in leads_list:
            lead_id = lead.get("id", "")
            if not lead_id: continue

            # Check if already synced
            existing = db.execute(text("SELECT id FROM crm_deals WHERE id = :id"), {"id": lead_id}).fetchone()
            if existing:
                stats["skipped"] += 1
                continue

            # Savepoint for each lead (so one failure doesn't kill the whole transaction)
            db.execute(text(f"SAVEPOINT sp_{lead_id.replace('-','_')}"))
            try:
                # Company info
                company = lead.get("company") or {}
                if isinstance(company, str):
                    company = {"name": company, "short_name": company}
                company_name = company.get("name", "") or ""
                short_name = company.get("short_name", "") or company_name or lead_id

                # Create or find company
                company_id = None
                ebf = lead.get("ebf_integration") or {}
                cus_ref = ebf.get("customer_registry_ref", "") or ""
                if cus_ref:
                    company_id = cus_ref
                    existing_co = db.execute(text("SELECT id FROM crm_companies WHERE id = :id"), {"id": cus_ref}).fetchone()
                    if not existing_co:
                        hq = lead.get("headquarters") or {}
                        db.execute(text("""INSERT INTO crm_companies (id, name, domain, industry, size, website, address, notes, created_by)
                            VALUES (:id, :name, :domain, :ind, :size, :web, :addr, :notes, :cb)"""),
                            {"id": cus_ref, "name": company_name, "domain": short_name,
                             "ind": lead.get("industry","") or "", "size": lead.get("segment","") or "",
                             "web": company.get("website","") or "",
                             "addr": f"{hq.get('city','')}, {hq.get('country','')}",
                             "notes": f"Employees: {lead.get('employee_count','?')}, Revenue: {lead.get('revenue_eur','?')} EUR",
                             "cb": "github-sync"})
                        stats["companies"] += 1
                else:
                    company_id = f"CO-{lead_id}"
                    existing_co = db.execute(text("SELECT id FROM crm_companies WHERE id = :id"), {"id": company_id}).fetchone()
                    if not existing_co:
                        db.execute(text("""INSERT INTO crm_companies (id, name, domain, industry, notes, created_by)
                            VALUES (:id, :name, :domain, :ind, :notes, :cb)"""),
                            {"id": company_id, "name": company_name, "domain": short_name,
                             "ind": lead.get("industry","") or "", "notes": "", "cb": "github-sync"})
                        stats["companies"] += 1

                # Create contacts
                first_contact_id = None
                for ct in (lead.get("contacts") or []):
                    if not ct or not isinstance(ct, dict): continue
                    ct_name = ct.get("name", "") or ""
                    if not ct_name or ct_name.startswith("["):
                        continue
                    ct_id = f"CT-{lead_id}-{ct_name[:10].replace(' ','-')}"
                    existing_ct = db.execute(text("SELECT id FROM crm_contacts WHERE id = :id"), {"id": ct_id}).fetchone()
                    if not existing_ct:
                        db.execute(text("""INSERT INTO crm_contacts (id, company_id, name, email, phone, position, role_type, notes, created_by)
                            VALUES (:id, :cid, :name, :email, :phone, :pos, :role, :notes, :cb)"""),
                            {"id": ct_id, "cid": company_id, "name": ct_name,
                             "email": ct.get("email","") or "", "phone": ct.get("phone","") or "",
                             "pos": ct.get("role","") or "", "role": "champion" if ct.get("is_champion") else "kontakt",
                             "notes": f"Relationship: {ct.get('relationship_strength','?')}", "cb": "github-sync"})
                        stats["contacts"] += 1
                    if not first_contact_id:
                        first_contact_id = ct_id

                # Create deal
                rel = lead.get("relationship") or {}
                stage_raw = lead.get("stage", "PROSPECT") or "PROSPECT"
                stage = stage_map.get(stage_raw, stage_raw.lower())
                prob = CRM_STAGE_PROB.get(stage, 10)
                value = 0
                try: value = int(rel.get("contract_value_eur", 0) or 0)
                except: pass
                owner = rel.get("owner", "GF") or "GF"

                # Build notes
                notes_parts = []
                if lead.get("notes"): notes_parts.append(str(lead["notes"]).strip())
                if lead.get("fit_score"): notes_parts.append(f"Fit Score: {lead['fit_score']}")
                if lead.get("engagement_score"): notes_parts.append(f"Engagement: {lead['engagement_score']}")
                if lead.get("hot_lead"): notes_parts.append(f"🔥 HOT LEAD: {lead.get('hot_lead_reason','')}")
                if lead.get("priority"): notes_parts.append(f"Priority: {lead['priority']} - {lead.get('priority_reason','')}")
                if lead.get("tags") and isinstance(lead["tags"], list): notes_parts.append(f"Tags: {', '.join(str(t) for t in lead['tags'])}")
                notes_text = "\n".join(notes_parts)

                source_info = lead.get("source") or {}
                if isinstance(source_info, dict):
                    source_str = f"{source_info.get('channel','')} {source_info.get('subchannel','')} {source_info.get('referrer','')}".strip()
                else:
                    source_str = str(source_info)

                # Handle next_action (can be string or dict)
                na_raw = lead.get("next_action") or ""
                if isinstance(na_raw, dict):
                    na_str = na_raw.get("description", "") or na_raw.get("type", "")
                    na_date = na_raw.get("date") or lead.get("next_action_date")
                else:
                    na_str = str(na_raw)
                    na_date = lead.get("next_action_date")
                if isinstance(na_date, dict): na_date = None
                if na_date: na_date = str(na_date)[:10]  # ensure string date

                # Ensure created_at is a string
                ca_raw = lead.get("created") or lead.get("created_at") or datetime.utcnow().isoformat()
                if isinstance(ca_raw, dict): ca_raw = datetime.utcnow().isoformat()
                ca_str = str(ca_raw)

                db.execute(text("""INSERT INTO crm_deals (id, company_id, contact_id, title, stage, value, probability, source,
                    next_action, next_action_date, owner, notes, created_by, created_at)
                    VALUES (:id, :cid, :ctid, :title, :stage, :val, :prob, :src, :na, :nad, :owner, :notes, :cb, :ca)"""),
                    {"id": lead_id, "cid": company_id, "ctid": first_contact_id,
                     "title": f"{short_name} – {lead.get('industry','') or ''}",
                     "stage": stage, "val": value, "prob": prob, "src": source_str,
                     "na": na_str, "nad": na_date,
                     "owner": f"OWN-{owner}", "notes": notes_text, "cb": "github-sync",
                     "ca": ca_str})
                stats["deals"] += 1

                # Import contact_log as activities
                for log in (lead.get("contact_log") or []):
                    if not log or not isinstance(log, dict): continue
                    act_id = f"ACT-{lead_id}-{str(log.get('date',''))[:10]}"
                    existing_act = db.execute(text("SELECT id FROM crm_activities WHERE id = :id"), {"id": act_id}).fetchone()
                    if existing_act: continue
                    db.execute(text("""INSERT INTO crm_activities (id, deal_id, company_id, type, subject, description, created_by, created_at)
                        VALUES (:id, :did, :cid, :type, :subj, :desc, :cb, :ca)"""),
                        {"id": act_id, "did": lead_id, "cid": company_id,
                         "type": log.get("type", "note") or "note", "subj": str(log.get("notes",""))[:200],
                         "desc": f"Contact: {log.get('contact_person','')}\nOutcome: {log.get('outcome','')}\n{log.get('notes','')}",
                         "cb": log.get("logged_by", "github-sync") or "github-sync",
                         "ca": str(log.get("date", datetime.utcnow().isoformat()))})
                    stats["activities"] += 1

            except Exception as lead_err:
                db.execute(text(f"ROLLBACK TO SAVEPOINT sp_{lead_id.replace('-','_')}"))
                logger.warning(f"CRM Sync: skipping {lead_id}: {lead_err}")
                stats["skipped"] += 1
                if "errors" not in stats: stats["errors"] = []
                if len(stats.get("errors",[])) < 10:
                    stats["errors"].append(f"{lead_id}: {str(lead_err)[:120]}")
                continue

        db.commit()
        logger.info(f"CRM Sync complete: {stats}")
        return {"status": "synced", "stats": stats}
    except Exception as e:
        db.rollback()
        logger.error(f"CRM Sync error: {e}")
        import traceback; traceback.print_exc()
        raise HTTPException(500, f"Sync failed: {str(e)}")
    finally: db.close()

# ── BEATRIX Memory (GitHub-backed) ──────────────────
@app.get("/api/memory")
async def get_memory(user=Depends(require_auth)):
    """Read BEATRIX extended memory from GitHub"""
    import urllib.request, ssl, yaml
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        url = f"https://api.github.com/repos/{GH_REPO}/contents/data/beatrix/memory.yaml"
        req = urllib.request.Request(url, headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3.raw", "User-Agent": "BEATRIXLab"})
        content = urllib.request.urlopen(req, context=ctx, timeout=15).read().decode()
        data = yaml.safe_load(content) or {}
        return data
    except Exception as e:
        logger.error(f"Memory read error: {e}")
        return {"error": str(e)}

@app.post("/api/memory/add")
async def add_memory(request: Request, user=Depends(require_auth)):
    """Add a learning or decision to BEATRIX memory on GitHub"""
    import urllib.request, ssl, yaml, base64
    from datetime import date
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    body = await request.json()
    entry_type = body.get("type", "learning")  # learning or decision
    topic = body.get("topic", "").strip()
    content = body.get("content", "").strip()
    if not topic or not content:
        return JSONResponse({"error": "topic and content required"}, status_code=400)
    try:
        # Fetch current memory
        url = f"https://api.github.com/repos/{GH_REPO}/contents/data/beatrix/memory.yaml"
        req = urllib.request.Request(url, headers={"Authorization": f"token {GH_TOKEN}", "User-Agent": "BEATRIXLab"})
        existing = json.loads(urllib.request.urlopen(req, context=ctx, timeout=15).read())
        sha = existing["sha"]
        raw_url = f"https://api.github.com/repos/{GH_REPO}/contents/data/beatrix/memory.yaml"
        req2 = urllib.request.Request(raw_url, headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3.raw", "User-Agent": "BEATRIXLab"})
        data = yaml.safe_load(urllib.request.urlopen(req2, context=ctx, timeout=15).read().decode()) or {}
        today = date.today().isoformat()
        if entry_type == "decision":
            decisions = data.get("decisions", [])
            new_id = f"D{len(decisions)+1:03d}"
            decisions.append({"id": new_id, "topic": topic, "decision": content, "date": today})
            data["decisions"] = decisions
        else:
            learnings = data.get("learnings", [])
            new_id = f"L{len(learnings)+1:03d}"
            learnings.append({"id": new_id, "topic": topic, "lesson": content, "date": today})
            data["learnings"] = learnings
        data["metadata"]["last_updated"] = today
        # Push back
        yaml_content = yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
        put_data = json.dumps({"message": f"memory: {entry_type} {new_id} – {topic}", "content": base64.b64encode(yaml_content.encode()).decode(), "sha": sha, "branch": "main"}).encode()
        req3 = urllib.request.Request(url, data=put_data, method="PUT", headers={"Authorization": f"token {GH_TOKEN}", "Content-Type": "application/json", "User-Agent": "BEATRIXLab"})
        urllib.request.urlopen(req3, context=ctx, timeout=15)
        logger.info(f"Memory added: {new_id} by {user.get('sub','?')}")
        return {"ok": True, "id": new_id, "type": entry_type}
    except Exception as e:
        logger.error(f"Memory add error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

# ── Legacy Leads API (kept for backward compat) ──────
@app.get("/api/leads")
async def get_leads(user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        rows = db.execute(text("SELECT * FROM leads ORDER BY updated_at DESC")).fetchall()
        return [dict(r._mapping) for r in rows]
    except Exception as e:
        logger.error(f"Leads fetch error: {e}")
        return []
    finally: db.close()

@app.post("/api/leads")
async def create_lead(request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        import uuid
        data = await request.json()
        lead_id = str(uuid.uuid4())[:8]
        db.execute(text("""INSERT INTO leads (id, company, contact, email, stage, value, source, notes, created_by)
            VALUES (:id, :company, :contact, :email, :stage, :value, :source, :notes, :created_by)"""),
            {"id": lead_id, "company": data.get("company",""), "contact": data.get("contact",""),
             "email": data.get("email",""), "stage": data.get("stage","kontakt"),
             "value": data.get("value", 0), "source": data.get("source",""),
             "notes": data.get("notes",""), "created_by": user["sub"]})
        db.commit()
        return {"id": lead_id, "status": "created"}
    except Exception as e:
        db.rollback()
        logger.error(f"Lead create error: {e}")
        raise HTTPException(500, str(e))
    finally: db.close()

@app.put("/api/leads/{lead_id}")
async def update_lead(lead_id: str, request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        data = await request.json()
        sets = []
        params = {"id": lead_id}
        for field in ["company", "contact", "email", "stage", "value", "source", "notes"]:
            if field in data:
                sets.append(f"{field} = :{field}")
                params[field] = data[field]
        if not sets: return {"status": "no changes"}
        sets.append("updated_at = CURRENT_TIMESTAMP")
        db.execute(text(f"UPDATE leads SET {', '.join(sets)} WHERE id = :id"), params)
        db.commit()
        return {"status": "updated"}
    except Exception as e:
        db.rollback()
        logger.error(f"Lead update error: {e}")
        raise HTTPException(500, str(e))
    finally: db.close()

@app.delete("/api/leads/{lead_id}")
async def delete_lead(lead_id: str, user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        db.execute(text("DELETE FROM leads WHERE id = :id"), {"id": lead_id})
        db.commit()
        return {"status": "deleted"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally: db.close()

# ── Contexts / Ausgangslage API ────────────────────
@app.get("/api/contexts")
async def get_contexts(user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        rows = db.execute(text("SELECT * FROM contexts ORDER BY updated_at DESC")).fetchall()
        return [dict(r._mapping) for r in rows]
    except Exception as e:
        logger.error(f"Contexts fetch error: {e}")
        return []
    finally: db.close()

@app.post("/api/contexts")
async def create_context(request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        import uuid
        data = await request.json()
        ctx_id = str(uuid.uuid4())[:8]
        db.execute(text("""INSERT INTO contexts (id, client, project, domain, status, situation, goal, constraints, created_by)
            VALUES (:id, :client, :project, :domain, :status, :situation, :goal, :constraints, :created_by)"""),
            {"id": ctx_id, "client": data.get("client",""), "project": data.get("project",""),
             "domain": data.get("domain","OTH"), "status": data.get("status","aktiv"),
             "situation": data.get("situation",""), "goal": data.get("goal",""),
             "constraints": data.get("constraints",""), "created_by": user["sub"]})
        db.commit()
        return {"id": ctx_id, "status": "created"}
    except Exception as e:
        db.rollback()
        logger.error(f"Context create error: {e}")
        raise HTTPException(500, str(e))
    finally: db.close()

@app.put("/api/contexts/{ctx_id}")
async def update_context(ctx_id: str, request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        data = await request.json()
        sets = []
        params = {"id": ctx_id}
        for field in ["client", "project", "domain", "status", "situation", "goal", "constraints"]:
            if field in data:
                sets.append(f"{field} = :{field}")
                params[field] = data[field]
        if not sets: return {"status": "no changes"}
        sets.append("updated_at = CURRENT_TIMESTAMP")
        db.execute(text(f"UPDATE contexts SET {', '.join(sets)} WHERE id = :id"), params)
        db.commit()
        return {"status": "updated"}
    except Exception as e:
        db.rollback()
        logger.error(f"Context update error: {e}")
        raise HTTPException(500, str(e))
    finally: db.close()

@app.delete("/api/contexts/{ctx_id}")
async def delete_context(ctx_id: str, user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        db.execute(text("DELETE FROM contexts WHERE id = :id"), {"id": ctx_id})
        db.commit()
        return {"status": "deleted"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally: db.close()

# ── Feedback API ────────────────────────────────────
@app.post("/api/feedback")
async def create_feedback(request: Request, user=Depends(require_auth)):
    db = get_db()
    try:
        from sqlalchemy import text
        import uuid
        data = await request.json()
        fb_id = str(uuid.uuid4())[:8]
        db.execute(text("""INSERT INTO feedback (id, type, comment, screenshot, page, url, viewport, user_agent, created_by)
            VALUES (:id, :type, :comment, :screenshot, :page, :url, :viewport, :ua, :created_by)"""),
            {"id": fb_id, "type": data.get("type","bug"), "comment": data.get("comment",""),
             "screenshot": data.get("screenshot",""), "page": data.get("page",""),
             "url": data.get("url",""), "viewport": data.get("viewport",""),
             "ua": data.get("userAgent",""), "created_by": user["sub"]})
        db.commit()
        logger.info(f"Feedback from {user['sub']}: [{data.get('type')}] {data.get('comment','')[:60]}")
        return {"id": fb_id, "status": "created"}
    except Exception as e:
        db.rollback()
        logger.error(f"Feedback error: {e}")
        raise HTTPException(500, str(e))
    finally: db.close()

@app.post("/api/feedback/analyze")
async def analyze_feedback(request: Request, user=Depends(require_auth)):
    """AI-powered screen analysis: BEATRIX suggests improvements"""
    try:
        data = await request.json()
        screenshot = data.get("screenshot", "")
        page = data.get("page", "unknown")
        viewport = data.get("viewport", "")

        if not screenshot or not ANTHROPIC_API_KEY:
            return {"suggestions": []}

        # Extract base64 data from data URL
        img_data = screenshot.split(",")[1] if "," in screenshot else screenshot

        import urllib.request, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 600,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": img_data}},
                    {"type": "text", "text": f"""Du bist BEATRIX, eine Strategic Intelligence Suite. Analysiere diesen Screenshot der Seite '{page}' (Viewport: {viewport}).

Gib genau 3 konkrete, umsetzbare Verbesserungsvorschläge als JSON-Array zurück. Jeder Vorschlag hat:
- "type": "bug" | "ux" | "wunsch" | "performance"
- "title": kurzer Titel (max 40 Zeichen)
- "description": konkrete Beschreibung (max 80 Zeichen)
- "x": horizontale Position in Prozent (0-100) wo das Problem auf dem Screen ist
- "y": vertikale Position in Prozent (0-100) wo das Problem auf dem Screen ist
- "w": Breite des betroffenen Bereichs in Prozent (5-40)
- "h": Höhe des betroffenen Bereichs in Prozent (5-30)

Die Koordinaten sollen möglichst genau auf den relevanten UI-Bereich zeigen.
Fokussiere auf: UX-Verbesserungen, fehlende Features, visuelle Probleme, Barrierefreiheit.
Antworte NUR mit dem JSON-Array, kein anderer Text."""}
                ]
            }]
        }).encode()

        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=payload, method="POST", headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        })

        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        result = json.loads(resp.read())
        text = result.get("content", [{}])[0].get("text", "[]").strip()
        if text.startswith("```"): text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        suggestions = json.loads(text)
        logger.info(f"Feedback analyze for {user['sub']}: {len(suggestions)} suggestions")
        return {"suggestions": suggestions[:3]}

    except Exception as e:
        logger.error(f"Feedback analyze error: {e}")
        return {"suggestions": []}

@app.get("/api/feedback")
async def get_feedback(user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        from sqlalchemy import text
        rows = db.execute(text("SELECT id, type, comment, page, viewport, user_agent, status, created_by, created_at FROM feedback ORDER BY created_at DESC")).fetchall()
        return [dict(r._mapping) for r in rows]
    except Exception as e:
        logger.error(f"Feedback list error: {e}")
        return []
    finally: db.close()

@app.get("/api/feedback/{fb_id}/screenshot")
async def get_feedback_screenshot(fb_id: str, user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        from sqlalchemy import text
        row = db.execute(text("SELECT screenshot FROM feedback WHERE id = :id"), {"id": fb_id}).fetchone()
        if not row: raise HTTPException(404, "Not found")
        return {"screenshot": row[0]}
    finally: db.close()

@app.put("/api/feedback/{fb_id}")
async def update_feedback(fb_id: str, request: Request, user=Depends(require_auth)):
    if not user.get("admin"): raise HTTPException(403, "Nur Administratoren")
    db = get_db()
    try:
        from sqlalchemy import text
        data = await request.json()
        status = data.get("status", "neu")
        db.execute(text("UPDATE feedback SET status = :status WHERE id = :id"), {"id": fb_id, "status": status})
        db.commit()
        return {"status": "updated"}
    finally: db.close()
