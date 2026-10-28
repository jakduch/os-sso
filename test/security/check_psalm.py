#!/usr/bin/env python3

"""Prove the taint configuration finds unsafe framework input and honors narrow escaping."""

import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
result = subprocess.run(
    ["php", sys.argv[1], "--config=test/security/psalm-canary.xml", "--taint-analysis",
     "--threads=1", "--no-cache", "--output-format=json"],
    cwd=root, capture_output=True, text=True, check=False,
)
if result.returncode != 2:
    raise SystemExit(f"Psalm canaries must fail on unsafe fixtures, got {result.returncode}: {result.stderr[-2000:]}")
issues = json.loads(result.stdout)
expected = {(index, line.split("// expect: ", 1)[1].strip())
            for index, line in enumerate((root / "test/security/canaries/unsafe.php").read_text().splitlines(), 1)
            if "// expect: " in line}
found = {(issue["line_from"], issue["type"]) for issue in issues if Path(issue["file_name"]).name == "unsafe.php"}
if len(expected) != 5 or not expected.issubset(found) or any(Path(issue["file_name"]).name == "safe.php" for issue in issues):
    raise SystemExit(f"Incorrect taint model: {[(issue['type'], issue['file_name'], issue['line_from']) for issue in issues]}")
print("Psalm canaries detected all five unsafe framework flows and accepted scoped escaping/structured backend arguments.")
