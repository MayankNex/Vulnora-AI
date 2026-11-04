# Security checks and interpretation

Vulnora checks the public response from one landing-page request. It does not crawl paths, submit forms, authenticate, fuzz inputs, exploit issues, or assess application logic.

## Severity meanings
- **High:** an important baseline concern (for example, page served over HTTP).
- **Medium:** a defence-in-depth control was not observed.
- **Low:** a useful hardening header was not observed.

Severity is a prioritization hint, not proof of exploitability. A missing header may be intentional or implemented elsewhere.

## Remediation workflow
1. Confirm the finding manually.
2. Identify the actual hosting platform and configuration owner.
3. Back up the current configuration.
4. Review the platform-specific preview.
5. Apply in a staging environment first.
6. Test application behaviour and roll back if needed.
7. Re-scan with authorization.

## Safe use and deployment
Use only on assets you own or have written permission to assess. Run the Streamlit app locally or behind an authenticated, rate-limited deployment. Do not expose an unrestricted scanner as a public service. The hostname/IP validation is a basic safeguard, not a hardened SSRF boundary; do not use this app as a multi-tenant scanning service without network-level egress controls, DNS pinning, authentication, and security review.

## Known limitations
- One response only; no crawling or authenticated checks.
- TLS validation is performed by the HTTP client, but detailed certificate-chain analysis is not included.
- Cookie parsing is intentionally basic and may not capture multiple Set-Cookie headers from all server behaviours.
- Header presence does not assess whether a policy is correct.
- AI output can be wrong; treat it as an explanation, not authority.
