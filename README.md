# Vulnora AI 🛡️

AI-assisted, beginner-friendly website security posture checker. The first release performs passive checks on a public landing page: HTTPS, common security headers, and visible cookie flags. It does not exploit, brute-force, crawl, or modify websites.

## Safety
Only scan websites you own or have explicit permission to assess. The app requires an authorization confirmation. It blocks local/private/reserved IP targets and validates redirect destinations. Findings are recommendations, not proof of exploitability.

## Setup

```bash
git clone https://github.com/MayankNex/Vulnora-AI.git
cd Vulnora-AI
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Optional AI explanations require your own OPENAI_API_KEY in a local .env file. Never commit secrets.

## Current scope
- HTTPS and TLS verification
- CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy
- Frame protection and basic Set-Cookie flags
- Plain-language remediation and JSON export
- Optional AI explanations

This is an early-stage passive checker, not a penetration-testing tool. It does not assess application logic, APIs, authentication, or databases.

## Roadmap
- Platform-specific guidance for WordPress, Nginx, Apache and Cloudflare
- Owner-side configuration checks
- Reviewable patch previews and verification
- Scheduled monitoring with consent

MIT License.