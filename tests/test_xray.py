import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
from xray import clean_source, rename_decompiler_locals, rewrite_pointer_offsets


class XRayTests(unittest.TestCase):
    def test_renames_consistently(self):
        src = "int local_10h = 1; return local_10h;"
        out = rename_decompiler_locals(src)
        self.assertEqual(out, "int recovered_var_1 = 1; return recovered_var_1;")

    def test_does_not_rename_comments_or_strings(self):
        src = '// local_10h\nchar *s = "var_4"; int var_4 = 2;'
        out = rename_decompiler_locals(src)
        self.assertIn('// local_10h', out)
        self.assertIn('"var_4"', out)
        self.assertIn('recovered_var_1 = 2', out)

    def test_pointer_rewrite_requires_explicit_size(self):
        self.assertEqual(rewrite_pointer_offsets("p + 8"), "p + 8")
        self.assertEqual(rewrite_pointer_offsets("p + 8", 4), "p[2]")

    def test_mask_cleanup(self):
        self.assertIn("(uint32_t)(value)", clean_source("x = value & 0xffffffff;"))


if __name__ == "__main__":
    unittest.main()
