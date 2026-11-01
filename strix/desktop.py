# Copyright (c) 2026 w0otdev (Strix modifications)
# Licensed under the Apache License, Version 2.0.

"""Desktop build jobs. The compiler runs in a separate, cancellable process."""

import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORED_FOLDERS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    "build",
    "dist",
}
PYTHON_SUFFIXES = {".py", ".pyw"}


@dataclass(frozen=True)
class ProjectManifest:
    files: tuple[Path, ...]
    python_files: tuple[Path, ...]
    skipped: int
    directories: tuple[Path, ...] = ()


def scan_project(source: Path) -> ProjectManifest:
    files = []
    folders = []
    skipped = 0
    for folder, directories, names in os.walk(source, followlinks=False):
        if Path(folder) != source:
            folders.append(Path(folder).relative_to(source))
        retained = []
        for name in sorted(directories):
            path = Path(folder) / name
            if (
                name in IGNORED_FOLDERS
                or path.is_symlink()
                or getattr(path, "is_junction", lambda: False)()
            ):
                skipped += 1
            else:
                retained.append(name)
        directories[:] = retained
        for name in sorted(names):
            path = Path(folder) / name
            if path.is_symlink() or path.suffix in {".pyc", ".pyo"}:
                skipped += 1
            else:
                files.append(path.relative_to(source))
    return ProjectManifest(
        tuple(files),
        tuple(p for p in files if p.suffix.lower() in PYTHON_SUFFIXES),
        skipped,
        tuple(folders),
    )


@dataclass(frozen=True)
class BuildRequest:
    source: Path
    output: Path
    mode: int = 2
    style: str = "mine"
    protect: bool = True
    hide: bool = True
    more: bool = True

    def validate(self):
        if not self.source.is_file() and not self.source.is_dir():
            raise ValueError("Choose an existing Python file or project folder.")
        if self.source.resolve() == self.output.resolve():
            raise ValueError(
                "Choose an output path different from the original source."
            )
        if self.output.exists():
            raise ValueError("That output already exists. Choose a new file name.")
        if self.source.is_dir() and self.output.resolve().is_relative_to(
            self.source.resolve()
        ):
            raise ValueError("Choose an output folder outside the source project.")
        if not self.output.parent.is_dir():
            raise ValueError("The output folder does not exist.")
        if self.mode not in (1, 2, 3) or self.style not in ("mine", "legacy"):
            raise ValueError("Select a valid mode and runtime style.")


def default_output(source: Path) -> Path:
    candidate = source.with_name("strix-" + source.name)
    suffix = 2
    while candidate.exists():
        name = (
            f"strix-{source.name}-{suffix}"
            if source.is_dir()
            else f"strix-{source.stem}-{suffix}{source.suffix}"
        )
        candidate = source.with_name(name)
        suffix += 1
    return candidate


def _compile(
    request: BuildRequest,
    source: Path,
    staged: Path,
    events: queue.Queue,
    cancel: threading.Event,
    *,
    importable=False,
):
    command = [
        sys.executable,
        "-u",
        "-m",
        "strix",
        "-f",
        str(source),
        "-o",
        str(staged),
        "-m",
        str(request.mode),
        "--style",
        request.style,
    ]
    if importable:
        command.append("--importable")
    for enabled, flag in (
        (request.protect, "--no-protect"),
        (request.hide, "--no-hide"),
        (request.more, "--no-more"),
    ):
        if not enabled:
            command.append(flag)
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    with subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        creationflags=flags,
    ) as process:
        events.put(("process", process))
        if cancel.is_set():
            process.terminate()
        assert process.stdout is not None
        for line in process.stdout:
            events.put(
                (
                    "log",
                    line.rstrip().replace(
                        str(staged),
                        str(
                            source.relative_to(request.source)
                            if importable
                            else request.output
                        ),
                    ),
                )
            )
        code = process.wait()
    if cancel.is_set():
        return False
    if code != 0:
        raise ValueError(f"Could not compile {source.name}. Check the build log.")
    return True


def run_build(request: BuildRequest, events: queue.Queue, cancel: threading.Event):
    """Send log/process/done/error/cancelled events without touching GUI widgets."""
    try:
        request.validate()
        if cancel.is_set():
            events.put(("cancelled", None))
            return
        with tempfile.TemporaryDirectory(
            prefix=".strix-", dir=request.output.parent
        ) as folder:
            if request.source.is_dir():
                manifest = scan_project(request.source)
                if not manifest.python_files:
                    raise ValueError(
                        "The selected folder contains no Python source files."
                    )
                staged = Path(folder) / "project"
                staged.mkdir()
                for relative in manifest.directories:
                    (staged / relative).mkdir(parents=True, exist_ok=True)
                for index, relative in enumerate(manifest.files):
                    if cancel.is_set():
                        break
                    target = staged / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if relative.suffix.lower() in PYTHON_SUFFIXES:
                        if not _compile(
                            request,
                            request.source / relative,
                            target,
                            events,
                            cancel,
                            importable=True,
                        ):
                            break
                    else:
                        shutil.copy2(request.source / relative, target)
                    events.put(
                        ("progress", (index + 1, len(manifest.files), str(relative)))
                    )
                if cancel.is_set():
                    events.put(("cancelled", None))
                    return
                if request.output.exists():
                    raise ValueError(
                        "The output folder was created by another operation. Choose a new path."
                    )
                staged.rename(request.output)
            else:
                staged = Path(folder) / "build.py"
                if not _compile(request, request.source, staged, events, cancel):
                    events.put(("cancelled", None))
                    return
                data = staged.read_bytes()
                with request.output.open("xb") as output:
                    output.write(data)
            events.put(("done", request.output))
    except Exception as error:  # noqa: BLE001 - surface worker failures inside the UI.
        events.put(("error", str(error)))
