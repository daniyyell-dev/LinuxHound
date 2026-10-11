import json
import os
import stat
import tempfile
import unittest

from linuxhound.collector import collect
from linuxhound.parsers import parse_crontab, parse_getfacl, parse_sudoers, parse_unit
from linuxhound.sanitize import redact


class ParserTests(unittest.TestCase):
    def test_sudo_keeps_password_rules_conditional(self):
        rules, unresolved = parse_sudoers(
            "dev ALL=(root) /usr/bin/id\nbackup ALL=(root) NOPASSWD: /usr/bin/true\n",
            "/etc/sudoers.d/lab",
        )
        self.assertEqual(unresolved, [])
        self.assertFalse(rules[0]["nopasswd"])
        self.assertTrue(rules[1]["nopasswd"])

    def test_relative_unit_is_unresolved(self):
        unit, unresolved = parse_unit("[Service]\nExecStart=backup.sh\n", "backup.service", "/etc/systemd/system/backup.service")
        self.assertEqual(unit["resolution"], "unresolved")
        self.assertEqual(unit["absolute_paths"], [])
        self.assertTrue(unresolved)

    def test_absolute_unit_redacts_arguments(self):
        unit, unresolved = parse_unit(
            "[Service]\nUser=root\nExecStart=/usr/bin/python3 /opt/lab/backup.py --token super-secret-token-value\n",
            "backup.service",
            "/etc/systemd/system/backup.service",
        )
        self.assertEqual(unresolved, [])
        self.assertIn("/opt/lab/backup.py", unit["absolute_paths"])
        self.assertNotIn("super-secret-token-value", unit["sanitized_exec"])
        self.assertIn("[argument omitted]", unit["sanitized_exec"])

    def test_user_crontab_uses_the_file_name_as_the_account(self):
        jobs, unresolved = parse_crontab("*/5 * * * * /opt/lab/backup.py\n", "/var/spool/cron/crontabs/backup", "backup")
        self.assertEqual(unresolved, [])
        self.assertEqual(jobs[0]["user"], "backup")
        self.assertEqual(jobs[0]["absolute_paths"], ["/opt/lab/backup.py"])
        jobs, unresolved = parse_crontab("* * * * * root backup.sh\n", "/etc/crontab")
        self.assertEqual(jobs[0]["absolute_paths"], [])
        self.assertTrue(unresolved)

    def test_getfacl_mask(self):
        parsed = parse_getfacl("user::rwx\nuser:2003:rwx\ngroup::r--\nmask::r--\nother::---\n")
        self.assertEqual(parsed["mask"], 4)
        self.assertEqual(parsed["users"]["2003"], 7)

    def test_redact_leaves_ordinary_paths(self):
        self.assertEqual(redact("/opt/token/file"), "/opt/token/file")


class CollectorTests(unittest.TestCase):
    def test_collector_reads_metadata_and_not_secret_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            secret = os.path.join(root, "secret.txt")
            shadow = os.path.join(root, "shadow")
            unit = os.path.join(root, "backup.service")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("super-secret-token-value\n")
            with open(shadow, "w", encoding="utf-8") as handle:
                handle.write("root:$6$abcsecret\n")
            with open(unit, "w", encoding="utf-8") as handle:
                handle.write(" [Service]\nExecStart=/usr/bin/app --token super-secret-token-value\n")
            os.chmod(secret, 0o644)
            snapshot = collect([root], "lab-test", hostname="lab-test", timeout=20, max_files=200, max_depth=4)
            encoded = json.dumps(snapshot)
            self.assertNotIn("super-secret-token-value", encoded)
            self.assertNotIn("abcsecret", encoded)
            self.assertFalse(snapshot["scope"]["secret_contents_read"])
            self.assertEqual(snapshot["validation_evidence"], [])
            self.assertIn("not_collected", {account["password_status"] for account in snapshot["accounts"]})
            recorded = next(item for item in snapshot["files"] if item["path"] == secret)
            self.assertEqual(recorded["mode"], stat.S_IMODE(os.lstat(secret).st_mode))
            self.assertTrue(any(item["name"] == "backup.service" for item in snapshot["services"]))
            self.assertNotEqual(snapshot["coverage"]["sudo"], "complete")


if __name__ == "__main__":
    unittest.main()
