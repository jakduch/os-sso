import importlib.util
import tempfile
import unittest
from pathlib import Path


SOURCE = (
    Path(__file__).parents[2]
    / "src/opnsense/scripts/OPNsense/SSO/vpn_guard.py"
)
SPEC = importlib.util.spec_from_file_location("vpn_guard", SOURCE)
vpn_guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(vpn_guard)


class VpnGuardTest(unittest.TestCase):
    def test_saved_config_requires_instance_without_native_authentication(self):
        uuid = "11111111-1111-4111-8111-111111111111"

        self.assertTrue(vpn_guard.saved_config_valid(uuid, {uuid: ""}))
        self.assertFalse(vpn_guard.saved_config_valid(uuid, {uuid: "Local Database"}))
        self.assertFalse(vpn_guard.saved_config_valid(uuid, {}))
        self.assertFalse(vpn_guard.saved_config_valid(uuid, None))

    def test_saved_instances_only_reads_native_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.xml"
            config.write_text(
                """<opnsense><OPNsense><OpenVPN><Instances>
                <Instance uuid="11111111-1111-4111-8111-111111111111">
                    <various_flags>float</various_flags><authmode/>
                </Instance>
                <Instance uuid="22222222-2222-4222-8222-222222222222">
                    <authmode>Local Database</authmode>
                </Instance>
                </Instances></OpenVPN></OPNsense></opnsense>""",
                encoding="utf-8",
            )
            original = vpn_guard.CONFIG_XML
            vpn_guard.CONFIG_XML = config
            try:
                self.assertEqual(
                    {
                        "11111111-1111-4111-8111-111111111111": "",
                        "22222222-2222-4222-8222-222222222222": "Local Database",
                    },
                    vpn_guard.saved_instances(),
                )
            finally:
                vpn_guard.CONFIG_XML = original

    def test_generated_config_requires_the_exact_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "instance.conf"
            expected = 'auth-user-pass-verify "/usr/local/bin/os-sso staff" via-file'
            settings = {
                "config_file": str(config),
                "auth_directive": expected,
                "optional_directive": "auth-user-pass-optional",
            }

            config.write_text(expected + "\nauth-user-pass-optional\n", encoding="utf-8")
            self.assertTrue(vpn_guard.generated_config_valid(settings))

            config.write_text(
                expected + "\nauth-user-pass-verify /tmp/other via-env\nauth-user-pass-optional\n",
                encoding="utf-8",
            )
            self.assertFalse(vpn_guard.generated_config_valid(settings))

            config.write_text(expected + "\n", encoding="utf-8")
            self.assertFalse(vpn_guard.generated_config_valid(settings))


if __name__ == "__main__":
    unittest.main()
