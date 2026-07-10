# QRizon

Malicious QR code detection and risk analysis system. Upload a QR code image,
QRizon decodes it and runs it through a rule-based security heuristics engine,
returning a SAFE / SUSPICIOUS / DANGEROUS verdict with a numeric score and the
specific flags that were triggered.

- **Frontend:** Next.js 14 (App Router, client components), plain CSS
- **Backend:** FastAPI, deployed as a Vercel Serverless Function at `/api`
- **QR decoding:** OpenCV's built-in `QRCodeDetector` (no system libraries
  required), with `pyzbar` as an optional fallback if the `libzbar` system
  library happens to be available on the host

## Project structure

```
qrizon/
├── api/
│   └── index.py        # FastAPI backend (decoding + heuristics)
├── src/
│   └── app/
│       ├── layout.js
│       ├── page.js      # main dashboard UI
│       └── globals.css
├── package.json
├── requirements.txt
├── vercel.json
├── next.config.mjs
└── .gitignore
```

## Run locally

**Frontend**
```bash
npm install
npm run dev
```
This starts Next.js on http://localhost:3000.

**Backend** (in a separate terminal)
```bash
pip install -r requirements.txt
uvicorn api.index:app --reload --port 8000
```
When running locally, the frontend calls `/api/scan`, so either run both
through `vercel dev` (recommended, see below) or add a proxy/rewrite in
`next.config.mjs` pointing `/api/*` to `http://localhost:8000` during
development.

**Easiest local option — Vercel CLI**
```bash
npm install -g vercel
vercel dev
```
This runs the Next.js frontend and the Python serverless function together
on one port, exactly as it will behave in production.

## Deploy to GitHub + Vercel

### 1. Push the code to GitHub
```bash
cd qrizon
git init
git add .
git commit -m "Initial commit: QRizon"
git branch -M main
git remote add origin https://github.com/<your-username>/qrizon.git
git push -u origin main
```
(Create the empty `qrizon` repository on GitHub first via "New repository" —
don't initialize it with a README so there's no merge conflict.)

### 2. Deploy on Vercel
1. Go to https://vercel.com and sign in (GitHub login is easiest).
2. Click **Add New → Project**.
3. Select your `qrizon` GitHub repository and click **Import**.
4. Vercel auto-detects the Next.js frontend. No build settings need to
   change — the `vercel.json` file already tells Vercel to run
   `api/index.py` as a Python serverless function and route `/api/*`
   requests to it.
5. Click **Deploy**.
6. Wait for the build to finish (Vercel installs both `package.json` and
   `requirements.txt` dependencies automatically). You'll get a live URL
   like `https://qrizon.vercel.app`.

### 3. Redeploying after changes
Any `git push` to the `main` branch triggers an automatic redeploy — no
extra steps needed.

## How the risk scoring works

Every QR payload starts at a score of 100 and loses points as flags trigger:

| Flag | Points deducted |
|---|---|
| HTTP instead of HTTPS | -30 |
| Phishing keyword(s) found (login, verify, bank, secure, etc.) | -10 per keyword, capped at -35 |
| Raw IP address used as hostname | -30 |
| Known URL shortener | -15 |
| Suspicious/low-reputation TLD (.xyz, .top, .zip, ...) | -15 |
| `@` symbol in URL (hostname-spoofing trick) | -25 |
| Excessive subdomain chain | -10 |
| Punycode domain (`xn--...`) | -15 |

Final score maps to a verdict:
- **75–100 → SAFE**
- **40–74 → SUSPICIOUS**
- **0–39 → DANGEROUS**

## Notes on `pyzbar`

`pyzbar` is a Python wrapper around the native `libzbar` library. Vercel's
Python serverless runtime doesn't guarantee that system library is present,
so QRizon decodes primarily with OpenCV's built-in `QRCodeDetector`, which is
bundled entirely inside `opencv-python-headless` and needs no extra system
packages. If `libzbar` does happen to be available in your deployment
environment, `pyzbar` is used automatically as a secondary decoder.
