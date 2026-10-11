import unittest

from linuxhound.analyze import who_can
from linuxhound.synthetic import before_report, with_validation


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.report = before_report()

    def _has(self, edge_type, account, path):
        return any(
            edge["type"] == edge_type and edge["source"].endswith("/" + account)
            and edge["target"].endswith(path)
            for edge in self.report["edges"]
        )

    def test_effective_rights_are_distinguished(self):
        self.assertTrue(self._has("CanWrite", "2001", "/opt/lab/backup.py"))
        self.assertFalse(self._has("CanReplace", "2001", "/opt/lab/backup.py"))
        self.assertTrue(self._has("CanReplace", "2002", "/opt/lab/backup.py"))
        self.assertFalse(self._has("CanRead", "2002", "/home/app/notes"))
        self.assertFalse(self._has("CanWrite", "2003", "/opt/lab/secrets.dat"))
        self.assertTrue(self._has("CanRead", "2003", "/opt/lab/secrets.dat"))
        self.assertFalse(self._has("CanDelete", "2002", "/tmp/note"))
        self.assertTrue(self._has("CanCreate", "2002", "/tmp"))
        self.assertFalse(self._has("CanWrite", "2003", "/opt/ro/data"))
        self.assertFalse(self._has("CanExecute", "2003", "/usr/local/bin/runme"))

    def test_metadata_links_explain_files_without_creating_attack_paths(self):
        metadata = [edge for edge in self.report["edges"]
                    if edge["type"] in {"OwnedBy", "GroupOwnedBy", "Contains", "LinksTo"}]
        self.assertTrue(any(edge["type"] == "OwnedBy"
                            and edge["source"].endswith("/usr/local/bin/status")
                            and edge["target"].endswith("/0") for edge in metadata))
        self.assertTrue(any(edge["type"] == "Contains"
                            and edge["source"].endswith("/usr/local/bin")
                            and edge["target"].endswith("/usr/local/bin/status") for edge in metadata))
        self.assertTrue(any(edge["type"] == "LinksTo"
                            and edge["source"].endswith("/opt/lab/current")
                            and edge["target"].endswith("/opt/lab/backup.py") for edge in metadata))
        self.assertFalse(any(edge["type"] == "LinksTo"
                             and edge["source"].endswith("/opt/lab/external") for edge in metadata))
        evidence_ids = {record["id"] for record in self.report["evidence"]}
        for edge in metadata:
            self.assertTrue(edge["evidence_ids"])
            self.assertTrue(set(edge["evidence_ids"]).issubset(evidence_ids))
        path_ids = {step["edge_id"] for path in self.report["analysis"]["paths"] for step in path["steps"]}
        self.assertFalse(path_ids.intersection(edge["id"] for edge in metadata))

    def test_root_job_requires_a_named_invocation(self):
        writable = [path for path in self.report["analysis"]["paths"] if path["pattern"] == "writable-root-job"]
        self.assertTrue(any(path["account"] == "backup" for path in writable))
        self.assertTrue(all(path["conclusion"] == "conditional_attack_path" for path in writable))
        self.assertTrue(all(path["verified"] is False for path in writable))
        relative = "job/lab-01//etc/crontab:11"
        self.assertFalse(any(edge["source"] == relative and edge["type"] == "Invokes" for edge in self.report["edges"]))
        self.assertTrue(any("backup.sh" in note["summary"] for note in self.report["analysis"]["notes"]))

    def test_sudo_authentication_stays_conditional(self):
        sudo_paths = [path for path in self.report["analysis"]["paths"] if path["pattern"] == "sudo"]
        dev = next(path for path in sudo_paths if path["account"] == "dev")
        backup = next(path for path in sudo_paths if path["account"] == "backup")
        self.assertEqual(dev["authority"], "legitimate_administrator")
        self.assertEqual(dev["conclusion"], "conditional_administrator_authority")
        self.assertIn("authenticated sudo", " ".join(dev["prerequisites"]))
        self.assertFalse(dev["verified"])
        self.assertEqual(backup["authority"], "possible_unintended")
        self.assertNotEqual(backup["conclusion"], "verified_vulnerability")
        self.assertFalse(backup["verified"])

    def test_suid_capability_and_docker_are_not_confirmed(self):
        conclusions = {path["conclusion"] for path in self.report["analysis"]["paths"]}
        self.assertNotIn("verified_vulnerability", conclusions)
        self.assertFalse(any(path["pattern"] == "suid-execute" for path in self.report["analysis"]["paths"]))
        self.assertTrue(any(note["kind"] == "suid_not_a_path" for note in self.report["analysis"]["notes"]))
        self.assertTrue(any(note["kind"] == "capability_not_a_vulnerability" for note in self.report["analysis"]["notes"]))
        docker = [path for path in self.report["analysis"]["paths"] if path["pattern"] == "docker-group"]
        self.assertEqual(len(docker), 1)
        self.assertFalse(docker[0]["verified"])
        self.assertFalse(any(path["pattern"] == "docker-boundary" for path in self.report["analysis"]["paths"]))

    def test_who_can_includes_evidence_and_root_as_admin(self):
        readers = who_can(self.report, "/opt/lab/secrets.dat", "read")
        app = next(item for item in readers if item["account"] == "app")
        self.assertFalse(app["verified"])
        self.assertTrue(app["evidence_ids"])
        root = next(item for item in readers if item["account"] == "root")
        self.assertEqual(root["authority"], "legitimate_administrator")

    def test_supplied_validation_is_required_for_a_verified_label(self):
        validated = with_validation(self.report)
        matched = [
            path for path in validated["analysis"]["paths"]
            if path["pattern"] == "writable-root-job" and path["account"] == "backup"
        ]
        self.assertTrue(matched)
        self.assertTrue(all(path["verified"] and path["conclusion"] == "verified_vulnerability" for path in matched))
        untouched = [path for path in validated["analysis"]["paths"] if path["pattern"] == "sudo"]
        self.assertTrue(all(path["verified"] is False for path in untouched))


if __name__ == "__main__":
    unittest.main()
