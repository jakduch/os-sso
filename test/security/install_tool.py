#!/usr/bin/env python3

"""Install a checksum-pinned analysis tool without extracting arbitrary archive paths."""

import argparse
import hashlib
import io
import json
import os
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

catalogue = json.loads(Path(__file__).with_name("tools.json").read_text())
parser = argparse.ArgumentParser()
parser.add_argument("tool", choices=catalogue)
parser.add_argument("--directory", type=Path, required=True)
arguments = parser.parse_args()
tool = catalogue[arguments.tool]
request = urllib.request.Request(tool["url"], headers={"User-Agent": "os-sso-security-ci"})
for attempt in range(3):
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = response.read()
        break
    except (OSError, urllib.error.URLError):
        if attempt == 2:
            raise
        time.sleep(2)
if hashlib.sha256(payload).hexdigest() != tool["sha256"]:
    raise SystemExit(f"SHA-256 verification failed for {arguments.tool}")
arguments.directory.mkdir(parents=True, exist_ok=True)
target = arguments.directory / tool["file"]
if "archive_member" in tool:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        member = archive.getmember(tool["archive_member"])
        if not member.isfile():
            raise SystemExit("Expected a regular executable archive member")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit("Missing executable archive member")
        payload = extracted.read()
target.write_bytes(payload)
os.chmod(target, 0o700)
print(f"Installed {arguments.tool} {tool['version']} after SHA-256 verification")
