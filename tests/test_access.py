import unittest

from linuxhound.access import (
    can_create,
    can_delete,
    can_execute,
    can_list,
    can_read,
    can_replace,
    can_traverse,
    can_write_content,
    suid_honored,
)


def entry(path, kind, mode, uid=0, gid=0, acl=None, target=None):
    info = {"path": path, "type": kind, "mode": mode, "uid": uid, "gid": gid}
    if acl:
        info["acl"] = acl
    if target:
        info["symlink_target"] = target
    return info


MOUNTS = [
    {"path": "/", "fstype": "ext4", "flags": ["rw"]},
    {"path": "/usr/local", "fstype": "ext4", "flags": ["rw", "nosuid", "noexec"]},
    {"path": "/opt/ro", "fstype": "ext4", "flags": ["ro"]},
]


class AccessTests(unittest.TestCase):
    def test_acl_mask_limits_named_user_and_spares_owner(self):
        files = {
            "/": entry("/", "dir", 0o755),
            "/opt": entry("/opt", "dir", 0o755),
            "/opt/secret": entry("/opt/secret", "file", 0o640, acl={
                "user_obj": 7, "group_obj": 0, "other": 0, "mask": 4,
                "users": {"2003": 7}, "groups": {},
            }, uid=2002),
        }
        named = can_write_content(files, MOUNTS, 2003, {2003}, "/opt/secret")
        self.assertEqual(named.state, "denied")
        read = can_read(files, MOUNTS, 2003, {2003}, "/opt/secret")
        self.assertTrue(read.granted)
        owner = can_write_content(files, MOUNTS, 2002, {2002}, "/opt/secret")
        self.assertTrue(owner.granted)

    def test_ancestor_traversal_blocks_a_world_readable_file(self):
        files = {
            "/": entry("/", "dir", 0o755),
            "/home": entry("/home", "dir", 0o755),
            "/home/app": entry("/home/app", "dir", 0o700, uid=2003, gid=2003),
            "/home/app/notes": entry("/home/app/notes", "file", 0o644, uid=2003, gid=2003),
        }
        denied = can_read(files, MOUNTS, 2002, {2002}, "/home/app/notes")
        self.assertEqual(denied.state, "denied")
        self.assertEqual(denied.blocked_by, "/home/app")
        allowed = can_read(files, MOUNTS, 2003, {2003}, "/home/app/notes")
        self.assertTrue(allowed.granted)

    def test_directory_replace_requires_write_and_execute(self):
        files = {
            "/": entry("/", "dir", 0o755),
            "/opt": entry("/opt", "dir", 0o755),
            "/opt/lab": entry("/opt/lab", "dir", 0o775, gid=110),
            "/opt/lab/backup.py": entry("/opt/lab/backup.py", "file", 0o644),
        }
        self.assertTrue(can_replace(files, MOUNTS, 2002, {110}, "/opt/lab/backup.py").granted)
        files["/opt/lab"]["mode"] = 0o755
        self.assertEqual(can_replace(files, MOUNTS, 2002, {110}, "/opt/lab/backup.py").state, "denied")
        files["/opt/lab"]["mode"] = 0o777
        files["/opt/lab"]["mode"] = 0o722
        self.assertEqual(can_create(files, MOUNTS, 2002, {2002}, "/opt/lab").state, "denied")

    def test_sticky_directory_limits_deletion(self):
        files = {
            "/": entry("/", "dir", 0o755),
            "/tmp": entry("/tmp", "dir", 0o1777),
            "/tmp/note": entry("/tmp/note", "file", 0o644, uid=2003),
        }
        self.assertTrue(can_create(files, MOUNTS, 2002, {2002}, "/tmp").granted)
        self.assertEqual(can_delete(files, MOUNTS, 2002, {2002}, "/tmp/note").state, "denied")
        self.assertTrue(can_delete(files, MOUNTS, 2003, {2003}, "/tmp/note").granted)
        self.assertTrue(can_delete(files, MOUNTS, 0, {0}, "/tmp/note").granted)

    def test_mount_ro_and_noexec(self):
        files = {
            "/": entry("/", "dir", 0o755),
            "/opt": entry("/opt", "dir", 0o755),
            "/opt/ro": entry("/opt/ro", "dir", 0o755),
            "/opt/ro/data": entry("/opt/ro/data", "file", 0o666),
            "/usr": entry("/usr", "dir", 0o755),
            "/usr/local": entry("/usr/local", "dir", 0o755),
            "/usr/local/bin": entry("/usr/local/bin", "dir", 0o755),
            "/usr/local/bin/runme": entry("/usr/local/bin/runme", "file", 0o755),
        }
        self.assertEqual(can_write_content(files, MOUNTS, 2003, {2003}, "/opt/ro/data").state, "denied")
        self.assertTrue(can_read(files, MOUNTS, 2003, {2003}, "/opt/ro/data").granted)
        self.assertEqual(can_execute(files, MOUNTS, 2003, {2003}, "/usr/local/bin/runme").state, "denied")

    def test_symlink_and_suid_mount(self):
        files = {
            "/": entry("/", "dir", 0o755),
            "/opt": entry("/opt", "dir", 0o755),
            "/opt/current": entry("/opt/current", "symlink", 0o777, target="/opt/data"),
            "/opt/data": entry("/opt/data", "file", 0o644),
            "/opt/external": entry("/opt/external", "symlink", 0o777, target="/missing"),
            "/usr": entry("/usr", "dir", 0o755),
            "/usr/local": entry("/usr/local", "dir", 0o755),
            "/usr/local/bin": entry("/usr/local/bin", "dir", 0o755),
            "/usr/local/bin/status": entry("/usr/local/bin/status", "file", 0o4755),
        }
        self.assertTrue(can_read(files, MOUNTS, 2003, {2003}, "/opt/current").granted)
        self.assertEqual(can_read(files, MOUNTS, 2003, {2003}, "/opt/external").state, "unresolved")
        honored = suid_honored(files["/usr/local/bin/status"], MOUNTS)
        self.assertEqual(honored.state, "denied")
        self.assertIn("not a vulnerability", " ".join(honored.assumptions))

    def test_execute_without_list(self):
        files = {"/": entry("/", "dir", 0o755), "/gate": entry("/gate", "dir", 0o711)}
        self.assertTrue(can_traverse(files, MOUNTS, 2003, {2003}, "/gate").granted)
        self.assertEqual(can_list(files, MOUNTS, 2003, {2003}, "/gate").state, "denied")

    def test_missing_ancestor_is_unresolved(self):
        files = {"/opt/file": entry("/opt/file", "file", 0o666)}
        self.assertEqual(can_read(files, MOUNTS, 2003, {2003}, "/opt/file").state, "unresolved")


if __name__ == "__main__":
    unittest.main()
