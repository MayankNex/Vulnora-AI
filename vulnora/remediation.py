"""Human-reviewed configuration examples. These are previews, never auto-applied."""

PLATFORM_FIXES = {
    "Nginx": """# Add inside the relevant server block; test before reload.
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;
# Enable HSTS only after HTTPS works across all intended subdomains:
add_header Strict-Transport-Security "max-age=31536000" always;
""",
    "Apache": """# Add to the appropriate VirtualHost; ensure headers_module is enabled.
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
# Enable HSTS only after confirming HTTPS coverage:
Header always set Strict-Transport-Security "max-age=31536000"
""",
    "Cloudflare": """# Dashboard > Rules > Transform Rules > Modify Response Header.
# Add X-Content-Type-Options: nosniff
# Add Referrer-Policy: strict-origin-when-cross-origin
# Add a carefully tested Content-Security-Policy.
# Configure HSTS under SSL/TLS > Edge Certificates only after HTTPS validation.
""",
    "WordPress": """# Prefer a maintained security/header plugin or server-level configuration.
# Back up first; stage and test CSP because themes/plugins may require third-party assets.
# Enforce HTTPS in WordPress and at the hosting layer.
# Do not paste server directives into functions.php without understanding the hosting stack.
""",
}

def get_fix_preview(platform: str) -> str:
    return PLATFORM_FIXES.get(platform, "Choose a platform to view a safe configuration example.")
