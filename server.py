"""
BEA Lab - Document Upload API
Uploads are automatically pushed to GitHub: papers/evaluated/integrated/
"""
import os, uuid, json, base64, logging, hashlib, time, hmac
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, JSON
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
AUTH_PASSWORD = os.getenv("BEA_PASSWORD", "beatrix2026")
JWT_SECRET = os.getenv("JWT_SECRET", hashlib.sha256(AUTH_PASSWORD.encode()).hexdigest())
JWT_EXPIRY = int(os.getenv("JWT_EXPIRY", "86400"))  # 24h default

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bea-lab")

# ── Simple JWT implementation (no external dependency) ──────────
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_jwt(payload: dict) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_enc = _b64url_encode(json.dumps(payload).encode())
    sig_input = f"{header}.{payload_enc}".encode()
    sig = _b64url_encode(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest())
    return f"{header}.{payload_enc}.{sig}"

def verify_jwt(token: str) -> Optional[dict]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = _b64url_encode(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest())
        if not hmac.compare_digest(parts[2], expected_sig):
            return None
        payload = json.loads(_b64url_decode(parts[1]))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# ── Auth dependency ─────────────────────────────────────────────
async def require_auth(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    if not token:
        # Also check cookie
        token = request.cookies.get("bea_token", "")
    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Nicht autorisiert")
    return payload

Base = declarative_base()
_engine = None
_SessionLocal = None

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
                    conn.commit()
            except Exception:
                pass
            logger.info(f"DB connected: {DATABASE_URL[:50]}...")
        except Exception as e:
            logger.error(f"DB init error: {e}")
            _engine = None
            _SessionLocal = None
            raise HTTPException(503, "Datenbank nicht bereit")
    return _SessionLocal()

def push_to_github(filename, content_bytes):
    if not GH_TOKEN:
        logger.warning("GH_TOKEN not set, skipping GitHub push")
        return {"error": "GH_TOKEN not configured"}
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    path = f"{GH_UPLOAD_PATH}/{filename}"
    url = f"https://api.github.com/repos/{GH_REPO}/contents/{path}"
    sha = None
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"})
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        sha = resp.get("sha")
    except Exception:
        pass
    payload = {"message": f"Upload via BEA Lab: {filename}", "content": base64.b64encode(content_bytes).decode(), "branch": "main"}
    if sha:
        payload["sha"] = sha
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="PUT", headers={"Authorization": f"token {GH_TOKEN}", "Content-Type": "application/json", "Accept": "application/vnd.github.v3+json"})
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        html_url = resp.get("content", {}).get("html_url", "")
        result_sha = resp.get("content", {}).get("sha", "")
        logger.info(f"GitHub push OK: {path}")
        return {"url": html_url, "sha": result_sha, "path": path}
    except Exception as e:
        logger.error(f"GitHub push failed: {e}")
        return {"error": str(e)}

app = FastAPI(title="BEA Lab Upload API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
FRONTEND_DIR = Path(__file__).parent / "frontend"

class LoginRequest(BaseModel):
    password: str

class TextUploadRequest(BaseModel):
    title: str = "Untitled"
    content: str
    category: Optional[str] = "general"
    language: Optional[str] = "de"
    tags: Optional[List[str]] = []
    database: Optional[str] = "knowledge_base"

class DocumentResponse(BaseModel):
    id: str
    title: str
    source_type: str
    file_type: Optional[str] = None
    database_target: str
    status: str
    created_at: str
    github_url: Optional[str] = None

def extract_text(file_path, file_type):
    try:
        if file_type == "pdf":
            import fitz
            doc = fitz.open(file_path)
            text = "\n".join(page.get_text() for page in doc)
            doc.close()
            return text.strip()
        elif file_type == "docx":
            from docx import Document as DocxDoc
            doc = DocxDoc(file_path)
            return "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        elif file_type in ("txt", "md", "csv", "json"):
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception as e:
        return f"[Extraction error: {e}]"
    return ""

# ── Public routes ───────────────────────────────────────────────
@app.get("/")
async def root():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "BEA Lab Upload API", "docs": "/docs"}

@app.get("/static/{filepath:path}")
async def static_files(filepath):
    file_path = FRONTEND_DIR / filepath
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    raise HTTPException(404, "Not found")

@app.post("/api/login")
async def login(request: LoginRequest):
    if not hmac.compare_digest(request.password, AUTH_PASSWORD):
        logger.warning("Failed login attempt")
        raise HTTPException(401, "Falsches Passwort")
    token = create_jwt({
        "sub": "bea-user",
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY
    })
    logger.info("Successful login")
    response = JSONResponse({"token": token, "expires_in": JWT_EXPIRY})
    response.set_cookie(
        key="bea_token", value=token,
        max_age=JWT_EXPIRY, httponly=True, samesite="lax"
    )
    return response

@app.get("/api/auth/check")
async def check_auth(user=Depends(require_auth)):
    return {"authenticated": True, "user": user.get("sub")}

@app.get("/api/health")
async def health():
    db_ok = False
    try:
        db = get_db()
        db.close()
        db_ok = True
    except Exception:
        pass
    return {"status": "ok" if db_ok else "degraded", "database": "connected" if db_ok else "unavailable", "github": "configured" if GH_TOKEN else "not configured", "github_repo": GH_REPO, "timestamp": datetime.utcnow().isoformat()}

# ── Protected routes ────────────────────────────────────────────
@app.post("/api/upload", response_model=DocumentResponse)
async def upload_file(file: UploadFile = File(...), database: str = Form("knowledge_base"), user=Depends(require_auth)):
    ext = file.filename.split(".")[-1].lower() if file.filename else ""
    if ext not in {"pdf", "txt", "md", "docx", "csv", "json"}:
        raise HTTPException(400, f"Dateityp .{ext} nicht unterstuetzt")
    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(400, "Datei zu gross (max 50 MB)")
    file_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / f"{file_id}.{ext}"
    with open(file_path, "wb") as f:
        f.write(content_bytes)
    text_content = extract_text(str(file_path), ext)
    gh_result = push_to_github(file.filename, content_bytes)
    github_url = gh_result.get("url", None)
    gh_status = "indexed+github" if github_url else "indexed"
    db = get_db()
    try:
        doc = Document(id=file_id, title=file.filename or "Unnamed", content=text_content, source_type="file", file_type=ext, file_path=str(file_path), file_size=len(content_bytes), database_target=database, status=gh_status, github_url=github_url, doc_metadata={"original_filename": file.filename, "content_length": len(text_content), "github": gh_result})
        db.add(doc)
        db.commit()
        db.refresh(doc)
        return DocumentResponse(id=doc.id, title=doc.title, source_type=doc.source_type, file_type=doc.file_type, database_target=doc.database_target, status=doc.status, created_at=doc.created_at.isoformat(), github_url=doc.github_url)
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Datenbankfehler: {e}")
    finally:
        db.close()

@app.post("/api/text", response_model=DocumentResponse)
async def upload_text(request: TextUploadRequest, user=Depends(require_auth)):
    if not request.content.strip():
        raise HTTPException(400, "Inhalt darf nicht leer sein")
    filename = f"{request.title.replace(' ', '_').replace('/', '-')}.txt"
    gh_result = push_to_github(filename, request.content.encode("utf-8"))
    github_url = gh_result.get("url", None)
    db = get_db()
    try:
        doc = Document(title=request.title, content=request.content, source_type="text", database_target=request.database or "knowledge_base", category=request.category, language=request.language, tags=request.tags, status="indexed+github" if github_url else "indexed", github_url=github_url, doc_metadata={"content_length": len(request.content), "github": gh_result})
        db.add(doc)
        db.commit()
        db.refresh(doc)
        return DocumentResponse(id=doc.id, title=doc.title, source_type=doc.source_type, file_type=None, database_target=doc.database_target, status=doc.status, created_at=doc.created_at.isoformat(), github_url=doc.github_url)
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Datenbankfehler: {e}")
    finally:
        db.close()

@app.get("/api/documents")
async def list_documents(database: Optional[str] = None, limit: int = 50, user=Depends(require_auth)):
    db = get_db()
    try:
        query = db.query(Document).order_by(Document.created_at.desc())
        if database:
            query = query.filter(Document.database_target == database)
        return [DocumentResponse(id=d.id, title=d.title, source_type=d.source_type, file_type=d.file_type, database_target=d.database_target, status=d.status, created_at=d.created_at.isoformat(), github_url=d.github_url) for d in query.limit(limit).all()]
    finally:
        db.close()

@app.delete("/api/documents/{doc_id}")
async def delete_document(doc_id: str, user=Depends(require_auth)):
    db = get_db()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "Nicht gefunden")
        if doc.file_path and os.path.exists(doc.file_path):
            os.remove(doc.file_path)
        db.delete(doc)
        db.commit()
        return {"message": f"Geloescht: {doc.title}"}
    finally:
        db.close()
