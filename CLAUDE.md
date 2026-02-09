# BEATRIX Lab – Project Context

## Architecture
- **Frontend**: Single-file `index.html` (Navy-CI Design System)
- **Backend**: `server.py` (FastAPI + PostgreSQL)
- **Hosting**: Railway (backend), Vercel (frontend via FehrAdvice-Partners-AG/bea-lab-frontend)
- **Auth**: JWT-based, PBKDF2 password hashing, Resend email verification

## Repositories
- `gerhardfehr/bea-lab-upload` – Backend + Frontend backup
- `FehrAdvice-Partners-AG/bea-lab-frontend` – Vercel auto-deploy (index.html only)
- `FehrAdvice-Partners-AG/complementarity-context-framework` – Papers storage

## Key Files
- `index.html` – Complete frontend (HTML + CSS + JS, ~4000 lines)
- `server.py` – Complete backend (FastAPI, ~2200 lines)

## Database (PostgreSQL)
Tables: users, documents, chat_messages, user_insights, leads, contexts, feedback
User: beatrix, DB: beatrix

## Design System
- Navy: #1B365D, Teal: #2A7F8E, Orange: #E8A33D
- CSS vars: --navy-card, --border, --accent, --accent-light
- Font: System stack (-apple-system, BlinkMacSystemFont)

## Deployment
1. Edit server.py + index.html
2. `git add . && git commit -m "v3.x.x: description" && git push`
3. Railway auto-deploys from main branch
4. For frontend: also push index.html to FehrAdvice-Partners-AG/bea-lab-frontend

## Auth Flow
- Login → JWT with {sub, name, uid, admin, role} → SessionStorage
- Roles: researcher (default), sales (Leads+Ausgangslage), operations (Ausgangslage), admin (all)
- Admin emails configured via ADMIN_EMAILS env var

## Current Version: v3.15.0
Features: Ψ-Profiling, Model Building (Steps 0-6), SSE Streaming, Role-based Tabs,
Lead-Management, Ausgangslage/Kontext, Screenshot-Feedback Widget

## Testing
- Backend: `python server.py` (needs DATABASE_URL, JWT_SECRET env vars)
- Frontend: Open index.html or serve via backend at /
- API base: /api/...

## Important Notes
- index.html is a single monolithic file – search by function names
- All API endpoints require JWT Bearer token (except /api/register, /api/login, /api/health)
- Railway SSL needs 30-60 min after domain changes
- Resend API from Railway needs User-Agent: BEATRIXLab/3.4 header
- When pushing frontend changes, push to BOTH repos (gerhardfehr/bea-lab-upload AND FehrAdvice-Partners-AG/bea-lab-frontend)
