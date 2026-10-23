import json
from pathlib import Path

def test_environment_variables_loaded():
    """Test that environment variables are properly loaded"""
    # Check if SMTP settings can be read (they'll be None if not set)
    from email_service import SMTP_HOST, SMTP_PORT
    
    assert SMTP_HOST is not None
    assert SMTP_PORT is not None


def test_pwa_manifest_has_share_target_and_required_icons():
    manifest = json.loads(Path("static/manifest.json").read_text(encoding="utf-8"))
    assert manifest["display"] == "standalone"
    assert manifest["share_target"]["method"] == "POST"
    assert manifest["share_target"]["params"]["files"]
    for icon in manifest["icons"]:
        assert (Path("static") / icon["src"].removeprefix("/static/")).is_file()


def test_service_worker_does_not_cache_transfer_api_responses():
    worker = Path("static/sw.js").read_text(encoding="utf-8")
    assert "url.pathname.startsWith('/transfer')" in worker
    assert "return event.respondWith(fetch(request))" in worker
