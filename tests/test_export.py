import json
import unittest

from linuxhound.html_export import export_html
from linuxhound.opengraph import export_opengraph, validate_opengraph
from linuxhound.synthetic import before_report, injection_report


class ExportTests(unittest.TestCase):
    def test_html_escapes_untrusted_report_text(self):
        html = export_html(injection_report())
        self.assertNotIn("</script><img", html)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("\\u003c", html)
        self.assertIn("connect-src 'none'", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)
        self.assertIn("textContent", html)

    def test_opengraph_payload_matches_the_published_constraints(self):
        exported = export_opengraph(before_report())
        payload = exported["payload"]
        self.assertEqual(validate_opengraph(payload), [])
        self.assertEqual(set(payload["metadata"]), {"source_kind"})
        for node in payload["graph"]["nodes"]:
            self.assertNotIn(":", node["id"])
            self.assertEqual(len(node["kinds"]), 1)
            self.assertNotIn("objectid", node["properties"])
            self.assertTrue(node["id"].startswith("LH"))
        kinds = {edge["kind"] for edge in payload["graph"]["edges"]}
        self.assertIn("LH_SudoAllowsIfAuthenticated", kinds)
        self.assertNotIn("MemberOf", kinds)
        self.assertNotIn("AdminTo", kinds)
        self.assertTrue(all(edge["properties"]["verified"] is False for edge in payload["graph"]["edges"]))
        traversable = {
            item["name"]: item["is_traversable"]
            for item in exported["definition"]["relationship_kinds"]
        }
        self.assertTrue(traversable["LH_MemberOf"])
        self.assertFalse(traversable["LH_SudoAllowsIfAuthenticated"])
        self.assertFalse(traversable["LH_SudoAllows"])
        topics = {item["topic"] for item in exported["fidelity"]}
        self.assertIn("conditional privilege", topics)
        self.assertIn("missing evidence", topics)

    def test_validator_rejects_a_colon_id(self):
        payload = {"graph": {"nodes": [{"id": "bad:id", "kinds": ["LH_Account"]}], "edges": []}}
        self.assertTrue(validate_opengraph(payload))


if __name__ == "__main__":
    unittest.main()
