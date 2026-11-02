# Copyright (c) 2026 w0otdev (Strix modifications)
# Licensed under the Apache License, Version 2.0.

"""Desktop build jobs. The compiler runs in a separate, cancellable process."""

import concurrent.futures
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from .languages import (
    PYTHON_SUFFIXES,
    javascript_command,
    language_for,
    output_relative,
    require_language,
    validate_output,
)

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


@dataclass(frozen=True)
class ProjectManifest:
    files: tuple[Path, ...]
    python_files: tuple[Path, ...]
    skipped: int
    directories: tuple[Path, ...] = ()

    @property
    def source_files(self) -> tuple[Path, ...]:
        return tuple(path for path in self.files if language_for(path) is not None)


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
                or path.suffix.lower() in {".pyc", ".pyo", ".map"}
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
    hw_bind: bool = False
    py_lock: bool = True
    importable: bool = False
    junk: bool = True
    cff: bool = True
    anti_debug: bool = True
    anti_hook: bool = True
    anti_frame: bool = True
    anti_vm: bool = True
    anti_proxy: bool = True
    anti_httptoolkit: bool = True
    anti_pydc: bool = True
    anti_crack: bool = True

    def validate(self):
        if not self.source.is_file() and not self.source.is_dir():
            raise ValueError("Choose an existing source file or project folder.")
        if self.source.is_file():
            validate_output(self.source, self.output)
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
        java_folder = (
            self.source.is_file()
            and self.source.suffix.lower() == ".java"
            and not self.output.parent.exists()
            and not self.output.parent.is_symlink()
            and self.output.parent.parent.is_dir()
        )
        if not self.output.parent.is_dir() and not java_folder:
            raise ValueError("The output folder does not exist.")
        if self.mode not in (1, 2, 3) or self.style not in ("mine", "legacy"):
            raise ValueError("Select a valid mode and runtime style.")


def default_output(source: Path) -> Path:
    source = source.resolve()
    if source.is_file() and source.suffix.lower() == ".java":
        folder = source.with_name("strix-" + source.stem)
        index = 2
        while folder.exists() or folder.is_symlink():
            folder = source.with_name(f"strix-{source.stem}-{index}")
            index += 1
        return folder / source.name
    emitted = source if source.is_dir() else output_relative(source)
    candidate = emitted.with_name("strix-" + emitted.name)
    suffix = 2
    while candidate.exists() or candidate.is_symlink():
        name = (
            f"strix-{source.name}-{suffix}"
            if source.is_dir()
            else f"strix-{emitted.stem}-{suffix}{emitted.suffix}"
        )
        candidate = source.with_name(name)
        suffix += 1
    return candidate


def _rewrite_package(target: Path, relative: Path, files: tuple[Path, ...]):
    """Keep package entry points pointing at emitted JS without editing shell scripts."""
    if relative.name != "package.json":
        return
    outputs = {
        path: output_relative(path) for path in files if output_relative(path) != path
    }
    if not outputs:
        return
    original = target.read_text(encoding="utf-8-sig")
    package = json.loads(original)

    def rewrite(value):
        if isinstance(value, str):
            if value.startswith(("/", "#")) or ":" in value or "*" in value:
                return value
            key = Path(os.path.normpath(str(relative.parent / value)))
            emitted = outputs.get(key)
            if emitted is not None and emitted != key:
                result = os.path.relpath(emitted, relative.parent).replace(os.sep, "/")
                return "./" + result if value.startswith("./") else result
            return value
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, dict):
            return {key: rewrite(item) for key, item in value.items()}
        return value

    updated = dict(package)
    for field in ("main", "module", "bin", "exports", "imports", "browser"):
        if field in updated:
            updated[field] = rewrite(updated[field])
    if updated != package:
        target.write_text(
            json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )


def _compile(
    request: BuildRequest,
    source: Path,
    staged: Path,
    events: queue.Queue,
    cancel: threading.Event,
    *,
    importable=False,
):
    language = require_language(source)
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
    if importable or request.importable:
        command.append("--importable")
    if request.hw_bind:
        command.append("--hw-bind")
    for enabled, flag in (
        (request.protect, "--no-protect"),
        (request.hide, "--no-hide"),
        (request.more, "--no-more"),
        (request.py_lock, "--no-py-lock"),
        (request.junk, "--no-junk"),
        (request.cff, "--no-cff"),
        (request.anti_debug, "--no-anti-debug"),
        (request.anti_hook, "--no-anti-hook"),
        (request.anti_frame, "--no-anti-frame"),
        (request.anti_vm, "--no-anti-vm"),
        (request.anti_proxy, "--no-anti-proxy"),
        (request.anti_httptoolkit, "--no-anti-httptoolkit"),
        (request.anti_pydc, "--no-anti-pydc"),
        (request.anti_crack, "--no-anti-crack"),
    ):
        if not enabled:
            command.append(flag)
    if language.engine == "javascript":
        command = javascript_command(
            source, mode=request.mode, more=request.more, output=staged
        )
    elif language.engine in ("csharp", "java"):
        from .native import managed_command

        command = managed_command(
            source, mode=request.mode, more=request.more, output=staged
        )
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
        events.put(("log", f"{language.name}: {source.name}"))
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
        new_java_folder = not request.output.parent.exists()
        with tempfile.TemporaryDirectory(
            prefix=".strix-",
            dir=request.output.parent.parent
            if new_java_folder
            else request.output.parent,
        ) as folder:
            if request.source.is_dir():
                manifest = scan_project(request.source)
                if not manifest.source_files:
                    raise ValueError(
                        "The selected folder contains no supported source files."
                    )
                # Detect collisions before starting any compilation (.ts + .js, etc.).
                targets = {}
                for relative in manifest.files:
                    emitted = output_relative(relative)
                    key = os.path.normcase(str(emitted))
                    if key in targets:
                        raise ValueError(
                            f"Output collision: {targets[key]} and {relative} both emit {emitted}."
                        )
                    targets[key] = relative
                    if emitted in manifest.directories:
                        raise ValueError(f"Output collision with directory: {emitted}.")
                staged = Path(folder) / "project"
                staged.mkdir()
                for relative in manifest.directories:
                    (staged / relative).mkdir(parents=True, exist_ok=True)

                def _stage_file(relative: Path) -> Path | None:
                    if cancel.is_set():
                        return None
                    target = staged / output_relative(relative)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if language_for(relative) is not None:
                        if not _compile(
                            request,
                            request.source / relative,
                            target,
                            events,
                            cancel,
                            importable=True,
                        ):
                            return None
                        shutil.copymode(request.source / relative, target)
                    else:
                        src_item = request.source / relative
                        if src_item.is_symlink():
                            return None
                        shutil.copy2(src_item, target, follow_symlinks=False)
                        _rewrite_package(target, relative, manifest.files)
                    return relative

                total = len(manifest.files)
                done = 0
                if len(manifest.source_files) > 1:
                    workers = min(len(manifest.source_files), os.cpu_count() or 4, 4)
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
                publish = Path(folder) / "publish"
                publish.mkdir()
                staged = publish / request.source.name
                if not _compile(request, request.source, staged, events, cancel):
                    events.put(("cancelled", None))
                    return
                shutil.copymode(request.source, staged)
                if new_java_folder:
                    if (
                        request.output.parent.exists()
                        or request.output.parent.is_symlink()
                    ):
                        raise ValueError(
                            "The Java output folder was created by another operation."
                        )
                    publish.rename(request.output.parent)
                else:
                    data = staged.read_bytes()
                    with request.output.open("xb") as output:
                        output.write(data)
                    shutil.copymode(request.source, request.output)
            events.put(("done", request.output))
    except Exception as error:  # noqa: BLE001 - surface worker failures inside the UI.
        events.put(("error", str(error)))
