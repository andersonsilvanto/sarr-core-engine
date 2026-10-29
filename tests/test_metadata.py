import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from core import CoreOrchestrator, Persistence
from sarr_core.cli import _export_dashboard
from sarr_core.metadata import MetadataExportError, MetadataManager


class MetadataExportTests(unittest.TestCase):
    def test_exports_last_persisted_run_as_sanitized_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            persistence = Persistence(root / "engine.sqlite3", root / "audit.jsonl")
            try:
                engine = CoreOrchestrator(persistence=persistence)
                run = engine.create_run("simulation")
                output_path = root / "exports" / "metadata.json"

                exported = MetadataManager(
                    root / "engine.sqlite3"
                ).export_latest_run(output_path)

                self.assertEqual(exported, output_path)
                document = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(document["schema_version"], 1)
                self.assertEqual(document["run"]["run_id"], str(run.run_id))
                self.assertEqual(document["run"]["mode"], "simulation")
                self.assertEqual(len(document["events"]), 1)
            finally:
                persistence.close()

    def test_export_fails_closed_when_database_has_no_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            persistence = Persistence(root / "empty.sqlite3", root / "audit.jsonl")
            persistence.close()

            with self.assertRaisesRegex(MetadataExportError, "No persisted"):
                MetadataManager(root / "empty.sqlite3").export_latest_run(
                    root / "metadata.json"
                )

    def test_missing_database_does_not_create_an_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_path = root / "metadata.json"

            with self.assertRaisesRegex(MetadataExportError, "does not exist"):
                MetadataManager(root / "missing.sqlite3").export_latest_run(
                    output_path
                )
            self.assertFalse(output_path.exists())

    def test_dashboard_schema_is_exported_to_config(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exported = _export_dashboard()

        schema = json.loads(exported.read_text(encoding="utf-8"))
        self.assertEqual(schema["title"], "SARR-Core local dashboard configuration")
        self.assertIn("additionalProperties", schema)
        self.assertIn(str(exported), output.getvalue())


if __name__ == "__main__":
    unittest.main()
