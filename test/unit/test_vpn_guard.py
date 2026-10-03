#!/usr/bin/env python3

"""Regression tests for the OpenVPN guard manifest parser."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/opnsense/scripts/OPNsense/SSO/vpn_guard.py"
SPEC = importlib.util.spec_from_file_location("vpn_guard", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SOURCE}")
VPN_GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VPN_GUARD)


class LoadManifestTest(unittest.TestCase):
    """Exercise current and legacy representations of the instance map."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.original_manifest = VPN_GUARD.MANIFEST
        VPN_GUARD.MANIFEST = Path(self.temporary.name) / "openvpn-instances.json"

    def tearDown(self) -> None:
        VPN_GUARD.MANIFEST = self.original_manifest
        self.temporary.cleanup()

    def write_manifest(self, instances: object) -> None:
        VPN_GUARD.MANIFEST.write_text(
            json.dumps({"version": 1, "instances": instances}),
            encoding="utf-8",
        )

    def test_empty_instance_map(self) -> None:
        self.write_manifest({})
        self.assertEqual({}, VPN_GUARD.load_manifest())

    def test_legacy_empty_instance_list(self) -> None:
        self.write_manifest([])
        self.assertEqual({}, VPN_GUARD.load_manifest())

    @mock.patch.object(VPN_GUARD, "log")
    def test_non_empty_instance_list_is_rejected(self, log: mock.Mock) -> None:
        self.write_manifest([{"profile": "invalid"}])
        self.assertIsNone(VPN_GUARD.load_manifest())
        log.assert_called_once_with(
            "integration manifest has no instance map",
            VPN_GUARD.syslog.LOG_ERR,
        )


if __name__ == "__main__":
    unittest.main()
