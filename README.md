# Catch The Phish 🕷️

<img width="1352" height="668" alt="image" src="https://github.com/user-attachments/assets/c90e844f-00f1-4065-8f58-932d4c350e1d" />

An AI-powered phishing detection web app built with Flask. Scan URLs, analyze PDFs & APKs, view a live threat dashboard, and learn about phishing attacks.

## Features

- 🔍 **URL Scanner** — Single & bulk URL phishing detection
- 📊 **Analytics Dashboard** — Real-time threat statistics via MongoDB
- 📚 **Learn About Phishing** — Educational content
- 🕷️ **Live Crawler** — Real-time phishing URL crawler feed
- 📱 **APK Analyzer** — Android app malware detection
- 📄 **PDF Analyzer** — Phishing PDF detection

## Tech Stack

- **Backend**: Python / Flask / Flask-SocketIO
- **Database**: MongoDB (Atlas for production)
- **APIs**: VirusTotal, Google Safe Browsing
- **Frontend**: HTML, CSS, JavaScript

---

## Local Development

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/catch-the-phish.git
cd catch-the-phish
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set up environment variables
```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

### 4. Run locally
```bash
python app.py
```
Visit `http://localhost:5001`

---

## Deploy to Vercel

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/catch-the-phish.git
git push -u origin main
```

### 2. Connect to Vercel
- Go to [vercel.com](https://vercel.com) → **New Project**
- Import your GitHub repository
- Vercel auto-detects `vercel.json` — no extra config needed

### 3. Set Environment Variables in Vercel
In the Vercel dashboard → **Settings → Environment Variables**, add:

| Variable | Description |
|----------|-------------|
| `MONGODB_URI` | MongoDB Atlas connection string (e.g. `mongodb+srv://user:pass@cluster.mongodb.net/phishing_detection`) |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API key |
| `SAFE_BROWSING_API_KEY` | Your Google Safe Browsing API key |
| `SECRET_KEY` | Any random secret string (e.g. generate with `python -c "import secrets; print(secrets.token_hex(32))"`) |

### 4. Deploy
Click **Deploy**. Your app will be live at `https://your-project.vercel.app`.

---

## Environment Variables Reference

See [`.env.example`](.env.example) for all supported variables.

---

## Notes for Vercel

- File uploads (APK, PDF) use `/tmp` on Vercel — files are ephemeral per request (expected serverless behavior)
- Background threads (cache clearing, batch processor) only run in local mode
- MongoDB Atlas free tier (M0) works perfectly for this app
