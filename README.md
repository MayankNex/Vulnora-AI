# Vulnora AI 🛡️

**An AI-assisted, defensive website security baseline checker.** Built to help website owners understand common security configuration gaps in plain language.

[![Tests](https://github.com/MayankNex/Vulnora-AI/actions/workflows/tests.yml/badge.svg)](https://github.com/MayankNex/Vulnora-AI/actions/workflows/tests.yml)

## What it does

- Checks HTTPS and common security response headers.
- Reviews basic cookie flags visible on the landing-page response.
- Prioritizes findings with a transparent heuristic score.
- Shows manual configuration examples for Nginx, Apache, Cloudflare, and WordPress.
- Optionally explains findings using an OpenAI API key.
- Exports a JSON report.
- Runs basic unit tests in GitHub Actions.

## Quick start

Python 3.10+:

```bash
git clone https://github.com/MayankNex/Vulnora-AI.git
cd Vulnora-AI
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

AI explanations are optional. Copy `.env.example` to `.env`, add your own `OPENAI_API_KEY`, and restart. Never commit `.env` or share API keys.

## Safety first

Only scan websites you own or have explicit permission to assess. Vulnora performs a small number of passive requests to one landing page. It does not exploit vulnerabilities, brute-force, crawl, submit forms, authenticate, or change server configuration.

The hostname checks are basic safeguards, **not a hardened SSRF boundary**. Do not expose this as an unrestricted public or multi-tenant scanning service. Use authentication, rate limits, network egress controls, and a security review before any hosted deployment.

## Important limitations

This is not a penetration-testing tool, compliance certification, or guarantee that a site is secure. Header presence does not prove a policy is correct. The score is a simple heuristic based only on observed findings. Cookie parsing is basic. Application logic, APIs, authentication, databases, and business logic are out of scope.

See [Security scope and limitations](docs/SECURITY_AND_LIMITATIONS.md).

## Roadmap

- [x] Passive baseline checks
- [x] Manual platform-specific fix examples
- [x] Optional AI explanations
- [x] JSON export and CI tests
- [ ] Owner-authenticated configuration integrations
- [ ] More comprehensive test coverage and report formats
- [ ] Secure, consent-based monitoring

## License

MIT. See [LICENSE](LICENSE).
