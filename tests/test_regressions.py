import ast
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from strix import context
from strix.runtime import pipeline
from strix.transforms import hide_builtins

ROOT = Path(__file__).resolve().parents[1]


class TransformTests(unittest.TestCase):
    def execute(self, source):
        namespace = {context.QN("bd"): vars(__import__("builtins"))}
        namespace[context.QN("dec")] = lambda values: "".join(
            chr((value - context.OFF) ^ context.K) for value in values
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(source, namespace)
        return output.getvalue()

    def test_hidden_builtins_replace_loads(self):
        source = "print(len([1, 2]))"
        transformed = hide_builtins(source)
        self.assertNotEqual(transformed, ast.unparse(ast.parse(source)))
        self.assertEqual(self.execute(transformed), "2\n")

    def test_hidden_builtins_preserve_shadowed_names_and_super(self):
        source = (
            "def f(len):\n    return len + 1\n"
            "class A:\n    def value(self):\n        return 5\n"
            "class B(A):\n    def value(self):\n        return super().value()\n"
            "print(f(2), B().value())\n"
        )
        self.assertEqual(self.execute(hide_builtins(source)), "3 5\n")

    def test_no_protect_omits_inner_guard(self):
        with patch("strix.runtime.build_guard", return_value="") as guard:
            pipeline("print('ok')", protect=False)
        guard.assert_not_called()

    def test_generated_files_do_not_inject_author_or_repository_metadata(self):
        for style in ("mine", "legacy"):
            for protect in (False, True):
                with self.subTest(style=style, protect=protect):
                    generated = pipeline("print('ok')", style=style, protect=protect)
                    for marker in ("w0otdev", "github.com", '"PYTHON"'):
                        self.assertFalse(
                            marker in generated,
                            f"Generated output injects metadata: {marker}",
                        )

    def test_generated_program_preserves_output_without_warnings(self):
        source = (
            "def greet(name):\n    return f'Hello {name!r:>8}'\n"
            "print(greet('Strix'))\n"
            "print(b'hello', b'\\x00\\xff', True, 42, 3.14)\n"
            "print('Tiếng Việt 🦉', -0.0, 3j)\n"
            "match {'key': 1}:\n"
            "    case {'key': 1}:\n        print('matched')\n"
        )
        expected = self.execute(source)
        with tempfile.TemporaryDirectory() as directory:
            for style in ("mine", "legacy"):
                for mode in (1, 2, 3):
                    with self.subTest(style=style, mode=mode):
                        output = Path(directory) / "generated.py"
                        output.write_text(
                            pipeline(source, mode=mode, protect=False, style=style),
                            encoding="utf-8",
                            newline="\n",
                        )
                        result = subprocess.run(
                            [sys.executable, "-X", "utf8", "-W", "error", str(output)],
                            capture_output=True,
                            encoding="utf-8",
                            check=False,
                        )
                        self.assertEqual(
                            result.returncode, 0, result.stdout + result.stderr
                        )
                        self.assertEqual(result.stderr, "")
                        self.assertEqual(result.stdout, expected)


class CliTests(unittest.TestCase):
    def test_default_output_for_absolute_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "strix", "-f", str(source), "--no-protect"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(source.with_name("strix-sample.py").is_file())

    def test_invalid_mode_is_rejected(self):
        result = subprocess.run(
            [sys.executable, "-m", "strix", "-f", "unused.py", "-m", "4"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("invalid choice", result.stderr)


if __name__ == "__main__":
    unittest.main()
