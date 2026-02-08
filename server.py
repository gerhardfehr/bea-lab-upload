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
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, JSON, Boolean
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
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

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
                    # Auto-verify existing admin users
                    conn.execute(text("UPDATE users SET email_verified = TRUE WHERE is_admin = TRUE AND email_verified = FALSE"))
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

app = FastAPI(title="BEA Lab Upload API", version="3.4.0")

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
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"})
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
        token = create_jwt({"sub": user.email, "name": user.name, "uid": user.id, "admin": user.is_admin, "iat": int(time.time()), "exp": int(time.time()) + JWT_EXPIRY})
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
        token = create_jwt({"sub": user.email, "name": user.name, "uid": user.id, "admin": user.is_admin, "iat": int(time.time()), "exp": int(time.time()) + JWT_EXPIRY})
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
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"})
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

@app.get("/api/debug/test-reset-email")
async def debug_test_reset():
    """Temporary debug endpoint"""
    try:
        result = send_reset_email("gerhard.fehr@fehradvice.com", "Gerhard", "debug-test-token-123")
        return {"sent": result, "api_key_set": bool(RESEND_API_KEY), "email_from": EMAIL_FROM, "app_url": APP_URL}
    except Exception as e:
        return {"error": str(e), "api_key_set": bool(RESEND_API_KEY)}

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
        return [{"id": u.id, "email": u.email, "name": u.name, "is_active": u.is_active, "is_admin": u.is_admin, "email_verified": u.email_verified, "created_at": u.created_at.isoformat() if u.created_at else None, "last_login": u.last_login.isoformat() if u.last_login else None} for u in users]
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

@app.post("/api/upload", response_model=DocumentResponse)
async def upload_file(file: UploadFile = File(...), database: str = Form("knowledge_base"), user=Depends(require_auth)):
    ext = file.filename.split(".")[-1].lower() if file.filename else ""
    if ext not in {"pdf", "txt", "md", "docx", "csv", "json"}: raise HTTPException(400, f"Dateityp .{ext} nicht unterstuetzt")
    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE: raise HTTPException(400, "Datei zu gross (max 50 MB)")
    file_id = str(uuid.uuid4()); file_path = UPLOAD_DIR / f"{file_id}.{ext}"
    with open(file_path, "wb") as f: f.write(content_bytes)
    text_content = extract_text(str(file_path), ext)
    gh_result = push_to_github(file.filename, content_bytes)
    github_url = gh_result.get("url", None); gh_status = "indexed+github" if github_url else "indexed"
    db = get_db()
    try:
        doc = Document(id=file_id, title=file.filename or "Unnamed", content=text_content, source_type="file", file_type=ext, file_path=str(file_path), file_size=len(content_bytes), database_target=database, status=gh_status, github_url=github_url, uploaded_by=user.get("sub"), doc_metadata={"original_filename": file.filename, "content_length": len(text_content), "github": gh_result})
        db.add(doc); db.commit(); db.refresh(doc)
        return DocumentResponse(id=doc.id, title=doc.title, source_type=doc.source_type, file_type=doc.file_type, database_target=doc.database_target, status=doc.status, created_at=doc.created_at.isoformat(), github_url=doc.github_url)
    except Exception as e: db.rollback(); raise HTTPException(500, f"Datenbankfehler: {e}")
    finally: db.close()

@app.post("/api/text", response_model=DocumentResponse)
async def upload_text(request: TextUploadRequest, user=Depends(require_auth)):
    if not request.content.strip(): raise HTTPException(400, "Inhalt darf nicht leer sein")
    filename = f"{request.title.replace(' ', '_').replace('/', '-')}.txt"
    gh_result = push_to_github(filename, request.content.encode("utf-8"))
    github_url = gh_result.get("url", None)
    db = get_db()
    try:
        doc = Document(title=request.title, content=request.content, source_type="text", database_target=request.database or "knowledge_base", category=request.category, language=request.language, tags=request.tags, status="indexed+github" if github_url else "indexed", github_url=github_url, uploaded_by=user.get("sub"), doc_metadata={"content_length": len(request.content), "github": gh_result})
        db.add(doc); db.commit(); db.refresh(doc)
        return DocumentResponse(id=doc.id, title=doc.title, source_type=doc.source_type, file_type=None, database_target=doc.database_target, status=doc.status, created_at=doc.created_at.isoformat(), github_url=doc.github_url)
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
