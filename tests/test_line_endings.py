import unittest
from pathlib import Path

from sarr_core.simulation import _FILE_BASELINES


ROOT = Path(__file__).resolve().parents[1]


class LineEndingTests(unittest.TestCase):
    def test_baseline_files_use_lf_line_endings(self) -> None:
        for relative_path in _FILE_BASELINES:
            with self.subTest(path=relative_path):
                content = (ROOT / relative_path).read_bytes()
                self.assertNotIn(
                    b"\r\n",
                    content,
                    f"{relative_path} precisa usar LF para que o hash da baseline "
                    "seja portável. Após aplicar .gitattributes, restaure o arquivo "
                    f"com `git checkout -- {relative_path}`.",
                )

    def test_gitattributes_define_json_and_batch_line_endings(self) -> None:
        attributes_path = ROOT / ".gitattributes"
        self.assertTrue(attributes_path.is_file(), ".gitattributes não existe.")
        lines = attributes_path.read_text(encoding="utf-8").splitlines()
        self.assertIn("*.json text eol=lf", lines)
        self.assertIn("*.bat text eol=crlf", lines)


if __name__ == "__main__":
    unittest.main()
