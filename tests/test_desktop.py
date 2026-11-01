import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from strix.desktop import BuildRequest, default_output, run_build, scan_project


def collect(events):
    result = []
    while not events.empty():
        result.append(events.get_nowait())
    return result


class DesktopBuildTests(unittest.TestCase):
    def project(self, folder):
        source = Path(folder) / "source"
        package = source / "package"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(
            "from .core import Record, greet\n", encoding="utf-8"
        )
        (package / "core.py").write_text(
            '"""Public module documentation."""\n'
            "from __future__ import annotations\n"
            "from dataclasses import dataclass, KW_ONLY\n"
            "from pathlib import Path\n"
            "@dataclass\nclass Record:\n"
            '    """Record documentation."""\n'
            "    title: str\n    _: KW_ONLY\n    count: int = 3\n"
            "def greet(record: Record) -> str:\n"
            '    """Public function documentation."""\n'
            "    return record.title + ':' + str(record.count)\n"
            "def resource():\n"
            "    return Path(__file__).with_name('data.txt').read_text().strip()\n",
            encoding="utf-8",
        )
        (package / "data.txt").write_text("resource intact\n", encoding="utf-8")
        (source / "main.py").write_text(
            "from typing import get_type_hints\n"
            "from package import Record, greet\n"
            "from package.core import resource, __doc__\n"
            "print(greet(Record('hello', count=7)))\n"
            "print(resource())\n"
            "print(get_type_hints(greet)['return'] is str)\n"
            "print(__doc__)\nprint(greet.__doc__)\nprint(Record.__doc__)\n",
            encoding="utf-8",
        )
        (source / "empty-folder").mkdir()
        (source / ".git").mkdir()
        (source / ".git" / "config").write_text("ignore", encoding="utf-8")
        return source

    def test_project_round_trip_preserves_imports_resources_and_annotations(self):
        with tempfile.TemporaryDirectory() as folder:
            source = self.project(folder)
            original = {
                path.relative_to(source): path.read_bytes()
                for path in source.rglob("*")
                if path.is_file()
            }
            for mode, style in ((2, "mine"), (3, "legacy")):
                with self.subTest(mode=mode, style=style):
                    output = Path(folder) / f"protected-{mode}"
                    events = queue.Queue()
                    run_build(
                        BuildRequest(source, output, mode=mode, style=style),
                        events,
                        threading.Event(),
                    )
                    messages = collect(events)
                    self.assertEqual(messages[-1], ("done", output), messages)
                    result = subprocess.run(
                        [sys.executable, "-X", "utf8", "-W", "error", "main.py"],
                        cwd=output,
                        capture_output=True,
                        encoding="utf-8",
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(
                        result.stdout.splitlines(),
                        [
                            "hello:7",
                            "resource intact",
                            "True",
                            "Public module documentation.",
                            "Public function documentation.",
                            "Record documentation.",
                        ],
                    )
                    self.assertEqual(
                        (output / "package" / "data.txt").read_bytes(),
                        original[Path("package/data.txt")],
                    )
                    self.assertTrue((output / "empty-folder").is_dir())
                    self.assertFalse((output / ".git").exists())
                    self.assertNotEqual(
                        (output / "package" / "core.py").read_bytes(),
                        original[Path("package/core.py")],
                    )
                    progress = [
                        value[0] for kind, value in messages if kind == "progress"
                    ]
                    self.assertEqual(progress, list(range(1, 5)))
            for path, content in original.items():
                self.assertEqual((source / path).read_bytes(), content)

    def test_project_failure_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            source = self.project(folder)
            (source / "broken.py").write_text("def broken(\n", encoding="utf-8")
            output = Path(folder) / "protected"
            events = queue.Queue()
            run_build(BuildRequest(source, output), events, threading.Event())
            self.assertEqual(collect(events)[-1][0], "error")
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(folder).glob(".strix-*")), [])

    def test_cancel_running_build_discards_staged_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.py"
            source.write_text("print('hello')\n", encoding="utf-8")
            output = Path(folder) / "protected.py"
            events = queue.Queue()
            cancel = threading.Event()
            worker = threading.Thread(
                target=run_build, args=(BuildRequest(source, output), events, cancel)
            )
            worker.start()
            kind, process = events.get(timeout=10)
            self.assertEqual(kind, "process")
            cancel.set()
            if process.poll() is None:
                process.terminate()
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(collect(events)[-1][0], "cancelled")
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(folder).glob(".strix-*")), [])

    def test_existing_output_and_nested_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            source = self.project(folder)
            output = Path(folder) / "existing"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("untouched", encoding="utf-8")
            with self.assertRaises(ValueError):
                BuildRequest(source, output).validate()
            with self.assertRaises(ValueError):
                BuildRequest(source, source / "nested").validate()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")

    def test_manifest_and_default_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source = self.project(folder)
            manifest = scan_project(source)
            self.assertEqual(len(manifest.python_files), 3)
            self.assertEqual(len(manifest.files), 4)
            self.assertEqual(manifest.skipped, 1)
            (Path(folder) / "strix-source").mkdir()
            self.assertEqual(default_output(source).name, "strix-source-2")


if __name__ == "__main__":
    unittest.main()
