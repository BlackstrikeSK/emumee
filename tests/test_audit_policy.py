"""Audit policy comes from bounded guest metadata, including guest child views."""

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from emumee.audit_policy import SUBCATEGORIES
from emumee.enumeration_programs import enumeration_programs, enumeration_text
from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_native import build_host_winexec_probe


class AuditPolicyTests(unittest.TestCase):
    def test_policy_has_bounded_known_subcategories_and_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "persona.json"
            path.write_text(json.dumps({"audit_policy": {
                "read_allowed": True, "subcategories": {"Logon": "Success and Failure"}}}))
            persona = load_persona(path)
            self.assertTrue(persona["audit_policy"]["read_allowed"])
            self.assertEqual(persona["audit_policy"]["subcategories"], {"Logon": "Success and Failure"})
            invalid = ([], {"unexpected": True}, {"read_allowed": 1},
                       {"subcategories": []}, {"subcategories": {"Logon": True}},
                       {"subcategories": {"Unknown": "Success"}},
                       {"subcategories": {"Logon": "Success\nFailure"}})
            for policy in invalid:
                with self.subTest(policy=policy):
                    path.write_text(json.dumps({"audit_policy": policy}))
                    with self.assertRaisesRegex(ValueError, "audit_policy"):
                        load_persona(path)
            self.assertEqual(load_persona(None)["audit_policy"],
                             {"read_allowed": False, "subcategories": {}})

    def test_guest_child_policy_csv_metadata_and_access_denial(self):
        self.assertEqual(len(SUBCATEGORIES), 59)
        self.assertEqual(len({guid for _, _, guid in SUBCATEGORIES}), 59)
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "persona.json"
                path.write_text(json.dumps({"hostname": "AUDIT-GUEST", "audit_policy": {
                    "read_allowed": True, "subcategories": {"Logon": "Success and Failure",
                        "Process Creation": "Success", "File System": "Failure"}}}))
                persona = load_persona(path)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"auditpol.exe /get /category:* /r\0"
                parent[0x700:0x700 + len(command)] = command
                result = run_native(bytes(parent), inspect_pe(bytes(parent), "parent.exe"),
                                    persona, root / "child", [], 10, 100_000)
                self.assertFalse(result["errors"])
                rows = list(csv.DictReader(io.StringIO(result["console_output"]["stdout"])))
                self.assertEqual(len(rows), 59)
                policies = {row["Subcategory"]: row for row in rows}
                for name, value in (("Logon", "Success and Failure"), ("Process Creation", "Success"),
                                    ("File System", "Failure"), ("Registry", "No Auditing")):
                    self.assertEqual(policies[name]["Inclusion Setting"], value)
                    self.assertEqual(policies[name]["Machine Name"], "AUDIT-GUEST")
                self.assertEqual(policies["Process Creation"]["Subcategory GUID"],
                                 "{0cce922b-69ae-11d9-bed3-505054503030}")
                report = json.loads((root / "child" / result["engine_report"]).read_text())
                self.assertEqual(report["network_events"], [])
                self.assertTrue(any(event["event"] == "virtual_process_create" and event["success"] and
                                    event["path"].casefold() == r"C:\Windows\System32\auditpol.exe".casefold()
                                    for event in report["virtual_process_events"]))
                image = enumeration_programs(arch == "x64", persona)["auditpol.exe"]
                for index, args in enumerate((["/get", "/category:*"], ["/list", "/category"],
                    ["/list", "/subcategory:*"], ["/list", "/subcategory:*", "/v"])):
                    result = run_native(image, inspect_pe(image, "auditpol.exe"), persona,
                                        root / f"read-{index}", [], 10, 100_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], 0)
                    self.assertEqual(result["console_output"]["stdout"],
                                     enumeration_text("auditpol.exe", persona, " ".join(args)))
                for index, args in enumerate((["/set", "/category:*", "/success:disable"],
                    ["/clear"], ["/get", "/user:Administrator", "/category:*"],
                    ["/get", "/category:Unknown"], ["/backup", "/file:host.csv"])):
                    result = run_native(image, inspect_pe(image, "auditpol.exe"), persona,
                                        root / f"unsupported-{index}", [], 10, 100_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], 87)
                    self.assertEqual(result["console_output"]["stdout"], "")
                for admin, expected in ((False, 5), (True, 0)):
                    persona["user_is_admin"] = admin
                    persona["audit_policy"]["read_allowed"] = False
                    image = enumeration_programs(arch == "x64", persona)["auditpol.exe"]
                    result = run_native(image, inspect_pe(image, "auditpol.exe"), persona,
                                        root / f"permission-{admin}", [], 10, 100_000,
                                        guest_args=["/get", "/category:*"])
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], expected)
                    if not admin:
                        self.assertIn("Access is denied", result["console_output"]["stdout"])
                        self.assertNotIn("Success and Failure", result["console_output"]["stdout"])


if __name__ == "__main__":
    unittest.main()
