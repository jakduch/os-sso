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


class SavedFlagsTest(unittest.TestCase):
    """The local config parser is bounded and never accepts XML entities."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.original_config = VPN_GUARD.CONFIG_XML
        self.original_limit = VPN_GUARD.CONFIG_XML_MAX_BYTES
        VPN_GUARD.CONFIG_XML = Path(self.temporary.name) / "config.xml"

    def tearDown(self) -> None:
        VPN_GUARD.CONFIG_XML = self.original_config
        VPN_GUARD.CONFIG_XML_MAX_BYTES = self.original_limit
        self.temporary.cleanup()

    def write_config(self, document: str) -> None:
        VPN_GUARD.CONFIG_XML.write_text(document, encoding="utf-8")

    def test_reads_managed_instance_flags(self) -> None:
        self.write_config(
            """<opnsense><OPNsense><OpenVPN><Instances>
            <Instance uuid="12345678-1234-1234-1234-123456789abc">
              <authmode></authmode>
              <various_flags>auth-user-pass-optional,verb 3</various_flags>
            </Instance>
            </Instances></OpenVPN></OPNsense></opnsense>"""
        )
        self.assertEqual(
            {
                "12345678-1234-1234-1234-123456789abc": (
                    ["auth-user-pass-optional", "verb 3"],
                    "",
                )
            },
            VPN_GUARD.saved_flags(),
        )

    @mock.patch.object(VPN_GUARD, "log")
    def test_rejects_dtd_and_entity_declarations(self, log: mock.Mock) -> None:
        self.write_config(
            "<!DOCTYPE opnsense [<!ENTITY x 'expanded'>]><opnsense>&x;</opnsense>"
        )
        self.assertIsNone(VPN_GUARD.saved_flags())
        self.assertIn("DTD and entity declarations", log.call_args.args[0])

    @mock.patch.object(VPN_GUARD, "log")
    def test_rejects_oversized_config_before_parsing(self, log: mock.Mock) -> None:
        VPN_GUARD.CONFIG_XML_MAX_BYTES = 32
        self.write_config("<opnsense>" + ("x" * 64) + "</opnsense>")
        self.assertIsNone(VPN_GUARD.saved_flags())
        self.assertIn("document exceeds 32 bytes", log.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
