from vulnora.remediation import get_fix_preview


def test_supported_platform_has_preview():
    assert "X-Content-Type-Options" in get_fix_preview("Nginx")


def test_unknown_platform_returns_guidance():
    assert "Choose a platform" in get_fix_preview("Unknown")
