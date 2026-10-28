#!/usr/bin/env python3

"""Verify narrow fixture exceptions cannot hide a token, including one removed later."""

import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
scanner = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix="os-sso-gitleaks-") as directory:
    checkout = Path(directory)
    def git(*arguments: str) -> None:
        subprocess.run(["git", *arguments], cwd=checkout, check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.name", "Security Canary")
    git("config", "user.email", "security-canary@example.invalid")
    (checkout / "test/idp/authentik").mkdir(parents=True)
    (checkout / "repository").mkdir()
    (checkout / "test/security").mkdir()
    # Synthetic token, generated locally and never valid at GitHub or committed here.
    token = "ghp_" + secrets.token_hex(18)
    fixtures = {
        "test/idp/authentik/setup.sh": "OIDC_ISSUER=https://authentik.test:9443/application/o/opnsense/\n",
        "repository/bootstrap.sh": "EXPECTED_KEY_SHA256=3efc7a48172fb2f5efe0249de9064c771b902876e43332af28871a04b8b486e7\n",
    }
    fixtures["test/security/check_gitleaks.py"] = "".join(fixtures.values())
    for name, text in fixtures.items():
        (checkout / name).write_text(text + "GITHUB_TOKEN=" + token + "\n")
    git("add", ".")
    git("commit", "-qm", "unsafe synthetic fixture")
    for name, text in fixtures.items():
        (checkout / name).write_text(text)
    git("add", ".")
    git("commit", "-qm", "removed synthetic token")
    report = checkout / "result.json"
    result = subprocess.run(
        [scanner, "git", "--config", str(root / ".gitleaks.toml"), "--redact=100",
         "--no-banner", "--log-level=error", "--report-format=json", "--report-path", str(report), str(checkout)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 1 or not report.is_file():
        raise SystemExit("Gitleaks did not reject the historical synthetic leak")
    findings = json.loads(report.read_text())
    if {finding["File"] for finding in findings} != set(fixtures) or len(findings) != len(fixtures):
        raise SystemExit("Gitleaks fixture exceptions did not preserve detection of adjacent tokens")
    if any(finding["Secret"] != "REDACTED" for finding in findings):
        raise SystemExit("Gitleaks did not fully redact reported secrets")
print("Gitleaks detected removed synthetic tokens in all three narrowly allowlisted files; reports are redacted.")
