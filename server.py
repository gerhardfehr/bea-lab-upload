"""
BEA Lab – Document Upload API
FastAPI backend for uploading PDFs, texts, and documents into the BEATRIX knowledge base.

Setup:
    pip install fastapi uvicorn python-multipart sqlalchemy psycopg2-binary pymupdf python-docx
    uvicorn server:app --host 0.0.0.0 --port 8000 --reload

Environment Variables:
    DATABASE_URL=postgresql://user:pass@localhost:5432/beatrix
    UPLOAD_DIR=./uploads
"""

import os
import uuid
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ── Config ──────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost:5432/beatrix")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# ── Database Setup ──────────────────────────────────────────────────
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Document(Base):
    """Document metadata and content stored in the database."""
    __tablename__ = "documents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=True)
    source_type = Column(String(20), nullable=False)  # 'file' or 'text'
    file_type = Column(String(10), nullable=True)      # pdf, txt, md, docx, csv, json
    file_path = Column(String(1000), nullable=True)
    file_size = Column(Integer, nullable=True)
    database_target = Column(String(50), nullable=False, default="knowledge_base")
    category = Column(String(50), nullable=True)
    language = Column(String(10), nullable=True)
    tags = Column(JSON, nullable=True)
    metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(20), default="indexed")


# Create tables
Base.metadata.create_all(bind=engine)

# ── App ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="BEA Lab Upload API",
    description="Document upload and indexing for the BEATRIX Knowledge Base",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static frontend
FRONTEND_DIR = Path(__file__).parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ── Models ──────────────────────────────────────────────────────────
class TextUploadRequest(BaseModel):
    title: str = "Untitled"
    content: str
    category: Optional[str] = "general"
    language: Optional[str] = "de"
    tags: Optional[list[str]] = []
    database: Optional[str] = "knowledge_base"


class DocumentResponse(BaseModel):
    id: str
    title: str
    source_type: str
    file_type: Optional[str]
    database_target: str
    status: str
    created_at: str


# ── Text Extraction ─────────────────────────────────────────────────
def extract_text_from_pdf(file_path: str) -> str:
    """Extract text from PDF using PyMuPDF (fitz)."""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(file_path)
        text = ""
        for page in doc:
            text += page.get_text() + "\n"
        doc.close()
        return text.strip()
    except ImportError:
        raise HTTPException(500, "PyMuPDF not installed. Run: pip install pymupdf")


def extract_text_from_docx(file_path: str) -> str:
    """Extract text from DOCX using python-docx."""
    try:
        from docx import Document as DocxDoc
        doc = DocxDoc(file_path)
        return "\n".join(para.text for para in doc.paragraphs if para.text.strip())
    except ImportError:
        raise HTTPException(500, "python-docx not installed. Run: pip install python-docx")


def extract_text(file_path: str, file_type: str) -> str:
    """Extract text content based on file type."""
    if file_type == "pdf":
        return extract_text_from_pdf(file_path)
    elif file_type == "docx":
        return extract_text_from_docx(file_path)
    elif file_type in ("txt", "md", "csv", "json"):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    else:
        return ""


# ── API Endpoints ───────────────────────────────────────────────────
@app.get("/")
async def root():
    """Serve the upload frontend."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "BEA Lab Upload API", "docs": "/docs"}


@app.post("/api/upload", response_model=DocumentResponse)
async def upload_file(
    file: UploadFile = File(...),
    database: str = Form("knowledge_base")
):
    """
    Upload a file (PDF, TXT, MD, DOCX, CSV, JSON) and insert into the database.
    The file content is extracted and stored alongside metadata.
    """
    # Validate file type
    ext = file.filename.split(".")[-1].lower() if file.filename else ""
    allowed_types = {"pdf", "txt", "md", "docx", "csv", "json"}
    if ext not in allowed_types:
        raise HTTPException(400, f"Dateityp .{ext} nicht unterstützt. Erlaubt: {', '.join(allowed_types)}")

    # Validate database target
    valid_dbs = {"knowledge_base", "bcm_axioms", "research"}
    if database not in valid_dbs:
        raise HTTPException(400, f"Ungültige Datenbank: {database}")

    # Read and save file
    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(400, "Datei zu groß (max 50 MB)")

    # Save to disk
    file_id = str(uuid.uuid4())
    safe_filename = f"{file_id}.{ext}"
    file_path = UPLOAD_DIR / safe_filename
    with open(file_path, "wb") as f:
        f.write(content_bytes)

    # Extract text content
    try:
        text_content = extract_text(str(file_path), ext)
    except Exception as e:
        text_content = f"[Extraction failed: {str(e)}]"

    # Store in database
    db = SessionLocal()
    try:
        doc = Document(
            id=file_id,
            title=file.filename or "Unnamed",
            content=text_content,
            source_type="file",
            file_type=ext,
            file_path=str(file_path),
            file_size=len(content_bytes),
            database_target=database,
            status="indexed",
            metadata={
                "original_filename": file.filename,
                "content_length": len(text_content),
                "upload_timestamp": datetime.utcnow().isoformat()
            }
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)

        return DocumentResponse(
            id=doc.id,
            title=doc.title,
            source_type=doc.source_type,
            file_type=doc.file_type,
            database_target=doc.database_target,
            status=doc.status,
            created_at=doc.created_at.isoformat()
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Datenbankfehler: {str(e)}")
    finally:
        db.close()


@app.post("/api/text", response_model=DocumentResponse)
async def upload_text(request: TextUploadRequest):
    """
    Insert a text entry directly into the database.
    Useful for axiom definitions, notes, parameters, etc.
    """
    if not request.content.strip():
        raise HTTPException(400, "Inhalt darf nicht leer sein")

    valid_dbs = {"knowledge_base", "bcm_axioms", "research"}
    if request.database not in valid_dbs:
        raise HTTPException(400, f"Ungültige Datenbank: {request.database}")

    db = SessionLocal()
    try:
        doc = Document(
            title=request.title,
            content=request.content,
            source_type="text",
            database_target=request.database,
            category=request.category,
            language=request.language,
            tags=request.tags,
            status="indexed",
            metadata={
                "content_length": len(request.content),
                "upload_timestamp": datetime.utcnow().isoformat()
            }
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)

        return DocumentResponse(
            id=doc.id,
            title=doc.title,
            source_type=doc.source_type,
            file_type=None,
            database_target=doc.database_target,
            status=doc.status,
            created_at=doc.created_at.isoformat()
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Datenbankfehler: {str(e)}")
    finally:
        db.close()


@app.get("/api/documents")
async def list_documents(
    database: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """List all documents, optionally filtered by target database."""
    db = SessionLocal()
    try:
        query = db.query(Document).order_by(Document.created_at.desc())
        if database:
            query = query.filter(Document.database_target == database)
        docs = query.offset(offset).limit(limit).all()
        return [
            DocumentResponse(
                id=d.id,
                title=d.title,
                source_type=d.source_type,
                file_type=d.file_type,
                database_target=d.database_target,
                status=d.status,
                created_at=d.created_at.isoformat()
            ) for d in docs
        ]
    finally:
        db.close()


@app.get("/api/documents/{doc_id}")
async def get_document(doc_id: str):
    """Get full document details including content."""
    db = SessionLocal()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "Dokument nicht gefunden")
        return {
            "id": doc.id,
            "title": doc.title,
            "content": doc.content,
            "source_type": doc.source_type,
            "file_type": doc.file_type,
            "database_target": doc.database_target,
            "category": doc.category,
            "language": doc.language,
            "tags": doc.tags,
            "metadata": doc.metadata,
            "status": doc.status,
            "created_at": doc.created_at.isoformat()
        }
    finally:
        db.close()


@app.delete("/api/documents/{doc_id}")
async def delete_document(doc_id: str):
    """Delete a document from the database."""
    db = SessionLocal()
    try:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            raise HTTPException(404, "Dokument nicht gefunden")
        # Delete file if exists
        if doc.file_path and os.path.exists(doc.file_path):
            os.remove(doc.file_path)
        db.delete(doc)
        db.commit()
        return {"message": f"Dokument '{doc.title}' gelöscht"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally:
        db.close()


# ── Health Check ────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "bea-lab-upload",
        "timestamp": datetime.utcnow().isoformat()
    }
