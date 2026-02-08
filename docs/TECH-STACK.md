# BEATRIX – Technologie-Stack & Tools

## Übersicht

BEATRIX (The Strategic Intelligence Suite) wurde am 8. Februar 2026 in einer einzigen Session von v0 → v3.10 gebaut. Hier sind alle Tools, Services und Technologien die dabei zum Einsatz kamen.

---

## 1. Infrastruktur & Hosting

| Tool | Zweck | Details |
|------|-------|---------|
| **Railway** | Backend-Hosting (API + DB) | PaaS, Auto-Deploy via GitHub, PostgreSQL Add-on |
| **Vercel** | Frontend-Hosting | Static Site mit API-Proxy zu Railway (SSL-Lösung) |
| **Squarespace Domains** | DNS-Management | Custom Domain www.bea-lab.io, CNAME-Records |
| **PostgreSQL** (Railway) | Datenbank | Users, Documents, ChatMessages, Embeddings |
| **pgvector** | Vector-Extension (PostgreSQL) | Semantische Suche mit Cosine Similarity |

---

## 2. Backend / API

| Tool | Zweck | Details |
|------|-------|---------|
| **Python 3** | Programmiersprache | Gesamtes Backend |
| **FastAPI** | Web-Framework | REST API mit async Support |
| **SQLAlchemy** | ORM | Datenbank-Modelle (User, Document, ChatMessage) |
| **Uvicorn** | ASGI-Server | Production Server auf Railway |
| **psycopg2** | PostgreSQL-Driver | Verbindung zur Railway-DB |
| **bcrypt** | Passwort-Hashing | Sichere Speicherung der User-Passwörter |
| **PyJWT** | JSON Web Tokens | Authentifizierung (Bearer Tokens) |
| **hashlib (SHA256)** | Duplikat-Detection | Verhindert doppelte Uploads |

---

## 3. AI / Machine Learning

| Tool | Zweck | Details |
|------|-------|---------|
| **Claude API** (Anthropic) | Fast Path Chat | claude-sonnet-4-20250514, Knowledge-Base-gestützte Antworten |
| **Claude Code** (GitHub Actions) | Deep Path Analyse | Vollständiger Repo-Zugriff auf EBF Framework, 4-5 Min pro Anfrage |
| **Voyage AI** | Text-Embeddings | voyage-3-lite (512 Dimensionen), Free Tier 200M Tokens/Monat |
| **Hybrid Search** | 3-Tier Retrieval | Vector Search (70%) + PostgreSQL Fulltext (20%) + Keyword (10%) |

---

## 4. Frontend

| Tool | Zweck | Details |
|------|-------|---------|
| **HTML5 / CSS3 / JavaScript** | Single-Page Application | Vanilla JS, kein Framework |
| **Plus Jakarta Sans** | Typografie | Google Fonts, via CDN |
| **CSS Custom Properties** | Design System | Navy-Theme mit Accent-Farben |
| **Responsive Design** | Mobile Support | Media Queries für iPad/Mobile |

---

## 5. E-Mail & Kommunikation

| Tool | Zweck | Details |
|------|-------|---------|
| **Resend** | Transaktionale E-Mails | Verifizierung, Passwort-Reset, Einladungen |
| **bea-lab.io Domain** | Absender-Domain | SPF/DKIM verifiziert bei Resend |

---

## 6. Versionskontrolle & CI/CD

| Tool | Zweck | Details |
|------|-------|---------|
| **GitHub** | Code-Repository | gerhardfehr/bea-lab-upload (App), FehrAdvice-Partners-AG/complementarity-context-framework (EBF) |
| **GitHub Actions** | CI/CD + Claude Code | anthropics/claude-code-action@v1, Issue-basierter Deep Path |
| **GitHub API** | Programmatischer Push | Commits via REST API (Base64-encoded Content) |
| **Railway GraphQL API** | Deploy-Trigger | Automatischer Redeploy nach Push |

---

## 7. APIs & Externe Services

| Tool | Zweck | Details |
|------|-------|---------|
| **Anthropic Messages API** | LLM-Inference | /v1/messages Endpoint, System-Prompt mit KB-Kontext |
| **Voyage AI API** | Embedding-Generierung | /v1/embeddings, input_type: "query" vs "document" |
| **GitHub REST API v3** | Issue-Management | Create Issue → Poll Comments → Extract Answer |
| **Railway Backboard API** | Infrastructure-as-Code | GraphQL Mutations für Deploys & Env-Vars |
| **LinkedIn OAuth** | Social Login | Profil-Verknüpfung (vorbereitet) |

---

## 8. Sicherheit & Authentifizierung

| Tool | Zweck | Details |
|------|-------|---------|
| **JWT (HS256)** | Token-basierte Auth | 24h Expiry, Bearer-Token im Header |
| **bcrypt** | Passwort-Hashing | Salt Rounds, sichere Speicherung |
| **CORS Middleware** | Cross-Origin | Vercel ↔ Railway Kommunikation |
| **Domain-Whitelist** | Registrierungsschutz | Nur @fehradvice.com und @bea-lab.io |
| **E-Mail-Verifizierung** | Account-Validierung | 6-stelliger Code via Resend |
| **SSL/TLS** | Verschlüsselung | Automatisch via Vercel + Railway |

---

## 9. Datenbank-Schema

| Tabelle | Felder | Zweck |
|---------|--------|-------|
| **users** | id, email, name, password_hash, is_admin, is_verified, linkedin_url, expertise_tags, profile_photo_url | Benutzerverwaltung |
| **documents** | id, title, content, filename, sha256_hash, source_type, tags, category, database_target, embedding_json | Knowledge Base |
| **chat_messages** | id, user_id, question, answer, path, knowledge_score, issue_number | Chat-Historie |

---

## 10. Architektur-Patterns

| Pattern | Inspiration | Umsetzung |
|---------|-------------|-----------|
| **Two-Path Architecture** | AlphaGo (Neural Net + Tree Search) | Fast Path (Vector Search + Claude API, ~12s) + Deep Path (Claude Code, ~4.5 Min) |
| **Self-Learning Loop** | AlphaGo (jede Partie verbessert Netzwerk) | Jede Deep-Path-Antwort wird embedded und erweitert die KB für den Fast Path |
| **3+1 Choice Architecture** | EBF Axiom MD-1 | 3 kuratierte Optionen + 1 Custom bei jedem Workflow-Step |
| **Hybrid Search** | Information Retrieval Best Practices | Vector (semantisch) + Fulltext (PostgreSQL) + Keyword (fallback) |
| **EEE Workflow** | EBF METHOD-DESIGN | 9-Step Model-Building mit Progress-Bar und visuellen Karten |

---

## 11. Development-Workflow

Der gesamte Build lief über **Claude (Anthropic)** im Chat-Interface:

1. **Code-Generierung** → Claude schreibt Python (Backend) und HTML/CSS/JS (Frontend)
2. **GitHub Push** → Via GitHub REST API (Base64-encoded, programmatisch)
3. **Railway Deploy** → Via GraphQL Mutation (automatisch nach Push)
4. **Test** → Via curl/Python-Scripts gegen die Live-API
5. **Iterate** → Fehler erkennen, fixen, erneut deployen

Kein lokales Development-Setup nötig. Alles remote über APIs.

---

## 12. Versionshistorie

| Version | Feature | Haupt-Tools |
|---------|---------|-------------|
| v3.0 | Basis-Website + Registration | Railway, FastAPI, PostgreSQL |
| v3.1 | Admin-Dashboard | JWT Auth, User Management |
| v3.2 | E-Mail-Verifizierung | Resend API, DNS |
| v3.3 | Domain + SSL | Squarespace, CNAME |
| v3.4 | Passwort-Features | bcrypt, Resend |
| v3.5 | Frontend/Backend Split | Vercel, Railway, SHA256 |
| v3.6 | Profil-System | LinkedIn OAuth, File Upload |
| v3.7 | Chat + RAG | Claude API, Knowledge Base Search |
| v3.8 | GitHub Actions Integration | Claude Code Action, Issue-based Chat |
| v3.9 | AlphaGo-Architektur | Voyage AI, pgvector, Hybrid Search |
| v3.10 | Modell-Building | EEE Workflow, Choice Architecture UI |

---

## 13. Kosten (geschätzt, monatlich)

| Service | Plan | Kosten |
|---------|------|--------|
| Railway | Hobby | ~$5/Monat |
| Vercel | Free | $0 |
| Resend | Free (100 E-Mails/Tag) | $0 |
| Voyage AI | Free (200M Tokens/Monat) | $0 |
| Anthropic Claude API | Pay-per-use | ~$5-20/Monat |
| GitHub Actions | Free (2000 Min/Monat) | $0 |
| Squarespace Domain | bea-lab.io | ~$20/Jahr |
| **Total** | | **~$10-25/Monat** |
