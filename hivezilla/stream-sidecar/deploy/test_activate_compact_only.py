import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "activate_compact_only", Path(__file__).with_name("activate_compact_only.py")
)
DEPLOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOY)


class RollbackTests(unittest.TestCase):
    def test_restore_keeps_checkpoint_and_removes_failed_candidate_side_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "backup"
            backup.mkdir()
            database = root / "client.sqlite"
            for path, cursor in [(backup / "client.sqlite", "committed-before"),
                                 (database, "failed-candidate")]:
                with sqlite3.connect(path) as db:
                    db.execute("CREATE TABLE checkpoint(cursor TEXT)")
                    db.execute("INSERT INTO checkpoint VALUES(?)", (cursor,))
            database.chmod(0o640)
            old_database = DEPLOY.DATABASE
            DEPLOY.DATABASE = database
            try:
                # A stopped candidate can leave these names after a crash.
                for suffix in ("-wal", "-shm"):
                    Path(str(database) + suffix).write_bytes(b"failed-candidate")
                DEPLOY.restore_database(backup, (os.getuid(), os.getgid(), 0o640))
                with sqlite3.connect(database) as db:
                    self.assertEqual(db.execute("SELECT cursor FROM checkpoint").fetchone()[0],
                                     "committed-before")
                    self.assertEqual(db.execute("PRAGMA quick_check(1)").fetchone()[0], "ok")
                self.assertEqual(database.stat().st_mode & 0o777, 0o640)
                self.assertEqual(database.stat().st_uid, os.getuid())
                for suffix in ("-wal", "-shm"):
                    self.assertFalse(Path(str(database) + suffix).exists())
            finally:
                DEPLOY.DATABASE = old_database


if __name__ == "__main__":
    unittest.main()
