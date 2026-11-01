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
from strix.transforms import clean_try_except, hide_builtins, joinstr, obf_vars

ROOT = Path(__file__).resolve().parents[1]


class TransformTests(unittest.TestCase):
    def execute(self, source):
        namespace = {context.QN("bd"): vars(__import__("builtins"))}
        namespace[context.QN("dec")] = lambda values: "".join(
            chr((value - context.OFF) ^ ((context.K + _i_ * 0x5BD1E995) & 0xFFFFFFFF))
            for _i_, value in enumerate(values)
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

    def test_in_place_overwrite_is_rejected_without_truncating_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            original = "print('keep_me_intact')\n"
            source.write_text(original, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "strix", "-f", str(source), "-o", str(source)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_protected_output_runs_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            for style in ("mine", "legacy"):
                with self.subTest(style=style):
                    out = Path(directory) / f"prot_{style}.py"
                    code = pipeline("print('protected_ok')", mode=2, protect=True, style=style)
                    out.write_text(code, encoding="utf-8", newline="\n")
                    res = subprocess.run(
                        [sys.executable, str(out)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertEqual(res.stdout.strip(), "protected_ok")

                    # Tamper with header byte outside markers -> must fail with DIE_CODE
                    tampered = code.replace("# -*- coding: utf-8 -*-", "# -*- coding: utf-8 -*- ")
                    out.write_text(tampered, encoding="utf-8", newline="\n")
                    res_tampered = subprocess.run(
                        [sys.executable, str(out)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(res_tampered.returncode, 0)

    def test_ast_security_edge_cases(self):
        # 1. alias_expr with braces
        expr = context.alias_expr('{"a": 1}')
        self.assertEqual(eval(expr), {"a": 1})

        # 2. joinstr with non-string Constant
        node = joinstr(ast.JoinedStr(values=[ast.Constant(value=1), ast.Constant(value="a")]))
        self.assertEqual(eval(ast.unparse(node)), "1a")

        # 3. obf_vars with aliased imports, multi-imports, except as, and match/case
        src = (
            "import json as j\n"
            "import os, sys\n"
            "def f(sys):\n    return sys\n"
            "try:\n    1 / 0\nexcept ZeroDivisionError as err:\n    msg = str(err)\n"
            "match [42]:\n    case [x]:\n        print(j.dumps([x, f(1), len(msg) > 0, bool(sys.version)]))\n"
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(obf_vars(src), {})
        self.assertEqual(buf.getvalue().strip(), "[42, 1, true, true]")

        # 4. hide_builtins with MatchClass
        match_src = "match 7:\n    case int(v):\n        out = len([v])\n"
        ns2 = {context.QN("bd"): vars(__import__("builtins"))}
        ns2[context.QN("dec")] = lambda values: "".join(
            chr((value - context.OFF) ^ ((context.K + _i_ * 0x5BD1E995) & 0xFFFFFFFF))
            for _i_, value in enumerate(values)
        )
        exec(hide_builtins(match_src), ns2)
        self.assertEqual(ns2["out"], 1)

        # 5. clean_try_except & pipeline with from __future__ import annotations
        fut_src = "from __future__ import annotations\nx: int = 5\nprint(x)\n"
        compile(clean_try_except(fut_src), "<test>", "exec")
        pipeline(fut_src, mode=2, protect=True)

    def test_ponytail_regressions(self):
        from strix.cli import main
        from strix.literals import harden_literals

        # 1. Enum, NamedTuple, dataclass, and nested f-string format_spec under full pipeline
        complex_src = (
            "from dataclasses import dataclass\n"
            "from enum import Enum\n"
            "from typing import NamedTuple\n"
            "import marshal\n"
            "class Color(Enum):\n    RED = 1\n    BLUE = 2\n"
            "class Pt(NamedTuple):\n    x: int\n    y: int\n"
            "@dataclass\nclass Box:\n    w: int = 10\n    def area(self, h: int) -> int:\n        return self.w * h\n"
            "w, p = 6, 2\n"
            "raw = marshal.dumps((Color.RED.value, Pt(3, 4).x, Box().area(5), f'{3.14159:{w}.{p}f}'))\n"
            "print(marshal.loads(raw))\n"
        )
        harden_literals("w, p = 6, 2\n_ = f'{3.14159:{w}.{p}f}'\n")
        self.assertIsNotNone(context.B(b"\x00\xff"))

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "complex_prot.py"
            out.write_text(
                pipeline(complex_src, mode=3, protect=True, hide=True, more=True),
                encoding="utf-8",
                newline="\n",
            )
            res = subprocess.run(
                [sys.executable, str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(res.stdout.strip(), "(1, 3, 50, '  3.14')")

            # 2. Unhandled user exception preserves non-zero exit code (not 0 and not DIE_CODE)
            err_out = Path(directory) / "err.py"
            err_out.write_text(
                pipeline("raise ValueError('boom')\n", mode=2, protect=True),
                encoding="utf-8",
                newline="\n",
            )
            err_res = subprocess.run(
                [sys.executable, str(err_out)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(err_res.returncode, 1)
            self.assertIn("ValueError: boom", err_res.stderr)

            # 3. Interactive --cli defaults more=True and delegates to run_headless
            sample = Path(directory) / "sample.py"
            sample.write_text("print('ok')\n", encoding="utf-8")
            inputs = iter([str(sample), "2", "", "", "", ""])
            with (
                patch("sys.argv", ["strix", "--cli"]),
                patch("builtins.input", side_effect=lambda *_: next(inputs)),
                patch("strix.cli.run_headless") as mock_headless,
            ):
                main()
            mock_headless.assert_called_once_with(
                str(sample),
                str(sample.with_name("strix-sample.py")),
                2,
                True,
                True,
                True,
            )


if __name__ == "__main__":
    unittest.main()
