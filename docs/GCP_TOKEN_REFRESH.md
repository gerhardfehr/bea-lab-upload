# GCP OAuth Token Refresh - BEATRIX NotebookLM Integration

## Wann wird das benötigt?

Wenn der Transform-Button in BEATRIX diesen Fehler zeigt:
```
Failed to create notebook: 'No GCP access token available. Configure GCP_REFRESH_TOKEN.'
```

Oder dieser Fehler in den Logs erscheint:
```
Error: invalid_grant
Description: reauth related error (invalid_rapt)
```

## Token-Lebensdauer

| Token | Gültigkeit |
|-------|------------|
| Access Token | 1 Stunde (automatisch erneuert) |
| Refresh Token | Unbegrenzt bei "Intern"-Apps |

Der Refresh Token kann ablaufen wenn:
- 6 Monate keine Nutzung
- User widerruft Zugriff in Google Account
- Client ID/Secret werden geändert

## Neuen Refresh Token generieren

### Schritt 1: OAuth Playground öffnen

1. Öffne: https://developers.google.com/oauthplayground/

2. Klicke auf ⚙️ (Zahnrad oben rechts)

3. Aktiviere: ☑️ "Use your own OAuth credentials"

4. Hole Client ID und Secret aus Railway:
   - Railway Dashboard → bea-lab-upload → Variables
   - `GCP_OAUTH_CLIENT_ID`
   - `GCP_OAUTH_CLIENT_SECRET`

### Schritt 2: Token generieren

5. Links unter "Step 1", gib diesen Scope ein:
   ```
   https://www.googleapis.com/auth/cloud-platform
   ```

6. Klicke **"Authorize APIs"**

7. Einloggen mit Google Account (der Zugriff auf GCP Projekt hat)

8. Klicke **"Exchange authorization code for tokens"**

9. Kopiere den **Refresh token** (beginnt mit `1//`)

### Schritt 3: Token in Railway eintragen

**Option A: Railway Dashboard**
1. Öffne: https://railway.app/project/71bbbb54-ee68-4926-994d-e850bfdd8816
2. Klicke auf den bea-lab-upload Service
3. Variables → `GCP_REFRESH_TOKEN`
4. Wert ersetzen → Save
5. Redeploy wird automatisch ausgelöst

**Option B: Via Claude**
Sage Claude: "Der GCP Refresh Token ist abgelaufen, hier ist der neue: 1//04..."
Claude trägt ihn automatisch in Railway ein.

## GCP Projekt Details

- **Project Number:** 368877792942
- **Project Name:** Beatrix
- **Location:** eu
- **OAuth App Status:** Intern (kein 7-Tage-Limit)
- **Console:** https://console.cloud.google.com/apis/credentials?project=368877792942

## Test ob Token funktioniert

In BEATRIX:
1. Stelle eine Frage
2. Klicke auf 🎙️ Transform
3. Modal sollte durchlaufen und NotebookLM Link zeigen

## Credentials Speicherort

Alle Credentials sind in Railway Environment Variables:
- `GCP_OAUTH_CLIENT_ID`
- `GCP_OAUTH_CLIENT_SECRET`
- `GCP_REFRESH_TOKEN`
- `GCP_PROJECT_NUMBER`
- `GCP_NOTEBOOKLM_LOCATION`

---

*Letzte Aktualisierung: 15. Februar 2026*
