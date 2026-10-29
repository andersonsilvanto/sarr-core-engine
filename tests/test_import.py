import unittest

import sarr_core


class PackageImportTest(unittest.TestCase):
    def test_package_imports_with_version(self) -> None:
        self.assertTrue(sarr_core.__version__)


if __name__ == "__main__":
    unittest.main()
