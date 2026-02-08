# BEATRIX Deployment Guide

## Architektur

```
www.bea-lab.io → Vercel (Frontend)
                    ↓ API calls
              Railway (Backend API + DB)
```

## WICHTIG: Zwei Repos!

| Repo | Hosting | Auto-Deploy |
|------|---------|-------------|
| `gerhardfehr/bea-lab-upload` | Railway | ✅ Bei Push auf main |
| `FehrAdvice-Partners-AG/bea-lab-frontend` | Vercel | ✅ Bei Push auf main |

## Deploy-Checkliste

### Nur Backend (server.py) ändern:
1. Push `server.py` → `gerhardfehr/bea-lab-upload`
2. Railway deploy triggern
3. Fertig ✅

### Nur Frontend (index.html) ändern:
1. Push `index.html` → `gerhardfehr/bea-lab-upload` (Backup)
2. Push `index.html` → `FehrAdvice-Partners-AG/bea-lab-frontend` ← **NICHT VERGESSEN!**
3. Vercel deployed automatisch
4. Fertig ✅

### Beides ändern:
1. Push `server.py` → `gerhardfehr/bea-lab-upload`
2. Railway deploy triggern
3. Push `index.html` → `gerhardfehr/bea-lab-upload`
4. Push `index.html` → `FehrAdvice-Partners-AG/bea-lab-frontend` ← **NICHT VERGESSEN!**
5. Fertig ✅

## Tokens & IDs

- GitHub Token: In Projekt-Konfiguration
- Railway API Token: In Projekt-Konfiguration
- Railway Service ID: 14a62e50-1e02-4b3f-a76f-982a565cace4
- Railway Environment ID: 36f908e9-278e-4073-a8d0-743e7a8dd5c7
