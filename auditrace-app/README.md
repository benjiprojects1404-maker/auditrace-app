# Auditrace

Static analysis for Solidity contracts and dapp/frontend code, built for chain 1404 (BlockDAG).

## Run locally

```
npm install
npm run dev
```

## Deploy to Vercel

**Option A — drag and drop (fastest, no git needed)**
On the Vercel "new project" screen, use the "drag and drop your project, or choose a file or a folder" option near the top (not "Import Git Repository", and not any of the template cards below it — those are unrelated starter projects). Drop this whole folder in. Vercel auto-detects Vite and sets the build command (`vite build`) and output directory (`dist`) correctly on its own.

**Option B — GitHub import (recommended if you'll keep iterating)**
1. Push this folder to a new GitHub repo.
2. On Vercel, "Import Git Repository" → GitHub → select the repo.
3. Framework preset: Vite (auto-detected). Deploy.
4. Every future `git push` auto-redeploys — no manual re-upload needed.

## Notes

- History persistence uses `localStorage`. Clearing browser data clears audit history.
- The "Fetch a deployed contract" feature calls WelshDAG's Blockscout API directly from the browser. It depends on WelshDAG's server sending permissive CORS headers and the contract being verified there — confirmed working as of the last deploy.
