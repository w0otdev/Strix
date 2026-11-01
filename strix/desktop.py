# Copyright (c) 2026 w0otdev (Strix modifications)
# Licensed under the Apache License, Version 2.0.

"""Desktop build jobs. The compiler runs in a separate, cancellable process."""

import concurrent.futures
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
                or name.startswith(".strix-")
                or path.is_symlink()
                or getattr(path, "is_junction", lambda: False)()
            ):
                skipped += 1
            else:
                retained.append(name)
        directories[:] = retained
        for name in sorted(names):
            path = Path(folder) / name
            if (
                path.is_symlink()
                or path.suffix in {".pyc", ".pyo"}
                or not path.is_file()
            ):
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
        if self.output.exists() or self.output.is_symlink():
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
    source = source.resolve()
    candidate = source.with_name("strix-" + source.name)
    suffix = 2
    while candidate.exists() or candidate.is_symlink():
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
        f"--file={source.resolve()}",
        f"--output={staged.resolve()}",
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

                def _stage_file(relative: Path) -> Path | None:
                    if cancel.is_set():
                        return None
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
                            return None
                    else:
                        src_item = request.source / relative
                        if src_item.is_symlink():
                            return None
                        shutil.copy2(src_item, target, follow_symlinks=False)
                    return relative

                total = len(manifest.files)
                done = 0
                if len(manifest.python_files) > 1:
                    workers = min(len(manifest.python_files), os.cpu_count() or 4)
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=workers
                    ) as pool:
                        futures = [
                            pool.submit(_stage_file, rel) for rel in manifest.files
                        ]
                        for future in concurrent.futures.as_completed(futures):
                            if cancel.is_set():
                                pool.shutdown(wait=False, cancel_futures=True)
                                break
                            try:
                                finished = future.result()
                            except Exception:
                                pool.shutdown(wait=False, cancel_futures=True)
                                raise
                            if finished is not None and not cancel.is_set():
                                done += 1
                                events.put(("progress", (done, total, str(finished))))
                else:
                    for relative in manifest.files:
                        if cancel.is_set():
                            break
                        finished = _stage_file(relative)
                        if finished is not None and not cancel.is_set():
                            done += 1
                            events.put(("progress", (done, total, str(finished))))
                if cancel.is_set():
                    events.put(("cancelled", None))
                    return
                if request.output.exists() or request.output.is_symlink():
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
