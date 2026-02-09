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
                    # Contexts / Ausgangslage table
                    conn.execute(text("""CREATE TABLE IF NOT EXISTS contexts (
                        id VARCHAR PRIMARY KEY, client VARCHAR(500),
                        project VARCHAR(500), domain VARCHAR(20),
                        status VARCHAR(50) DEFAULT 'aktiv',
                        situation TEXT, goal TEXT, constraints TEXT,
                        created_by VARCHAR(320),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""))
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
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
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
    if index_path.exists(): return FileResponse(str(index_path))
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
        token = create_jwt({"sub": user.email, "name": user.name, "uid": user.id, "admin": user.is_admin, "role": user.role or "researcher", "iat": int(time.time()), "exp": int(time.time()) + JWT_EXPIRY})
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
        token = create_jwt({"sub": user.email, "name": user.name, "uid": user.id, "admin": user.is_admin, "role": user.role or "researcher", "iat": int(time.time()), "exp": int(time.time()) + JWT_EXPIRY})
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
        return [{"id": u.id, "email": u.email, "name": u.name, "is_active": u.is_active, "is_admin": u.is_admin, "role": u.role or "researcher", "email_verified": u.email_verified, "created_at": u.created_at.isoformat() if u.created_at else None, "last_login": u.last_login.isoformat() if u.last_login else None} for u in users]
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
        if role not in ("researcher", "sales", "operations"):
            raise HTTPException(400, "Ungültige Rolle")
        target = db.query(User).filter(User.id == user_id).first()
        if not target: raise HTTPException(404, "Benutzer nicht gefunden")
        target.role = role; db.commit()
        logger.info(f"Role changed: {target.email} → {role}")
        return {"email": target.email, "role": role}
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
