# Copyright (c) 2026 w0otdev (Strix modifications)
# Original work Copyright (c) ktn1703 (https://github.com/ktn1703/Neo)
# Licensed under the Apache License, Version 2.0.
# Modified by w0otdev: Modularized and rebranded under Strix.

import argparse
import os
import queue
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

from .context import VER
from .desktop import BuildRequest, default_output, run_build
from .languages import (
    LANGUAGES,
    obfuscate_file,
    read_source,
    require_language,
    validate_output,
)

LOGO = r"""

     ___           ___           ___                       ___
    /\  \         /\  \         /\  \          ___        |\__\
   /::\  \        \:\  \       /::\  \        /\  \       |:|  |
  /:/\ \  \        \:\  \     /:/\:\  \       \:\  \      |:|  |
 _\:\~\ \  \       /::\  \   /::\~\:\  \      /::\__\     |:|__|__
/\ \:\ \ \__\     /:/\:\__\ /:/\:\ \:\__\  __/:/\/__/ ____/::::\__\
\:\ \:\ \/__/    /:/  \/__/ \/_|::\/:/  / /\/:/  /    \::::/~~/~
 \:\ \:\__\     /:/  /         |:|::/  /  \::/__/      ~~|:|~~|
  \:\/:/  /     \/__/          |:|\/__/    \:\__\        |:|  |
   \::/  /                     |:|  |       \/__/        |:|  |
    \/__/                       \|__|                     \|__|

    INFO AUTHOR: w0otdev
    TOOL OBF:    github.com/w0otdev/Strix
    BASED ON:    github.com/ktn1703/Neo (Apache-2.0)

"""


def stage(text, symbol="STRIX"):
    return f" [{symbol}] {text}"


def log_info(t):
    print(stage(t, "INFO"))


def log_event(t):
    print(stage(t, "EVENT"))


def log_ok(t):
    print(stage(t, "OK"))


def log_warn(t):
    print(stage(t, "WARN"))


def print_logo():
    print(LOGO)
    print(stage(f" Strix {VER} ", symbol="?"))


def parse_args():
    p = argparse.ArgumentParser(description="STRIX ULTIMATE OBFUSCATOR")
    interface = p.add_mutually_exclusive_group()
    interface.add_argument(
        "--gui", action="store_true", help="open the desktop interface"
    )
    interface.add_argument(
        "--cli", action="store_true", help="use the interactive terminal interface"
    )
    p.add_argument("-f", "--file", help="supported source file or project folder")
    p.add_argument(
        "--list-languages", action="store_true", help="list supported source formats"
    )
    p.add_argument(
        "--importable",
        action="store_true",
        help="preserve module APIs and annotations; omit single-file guards",
    )
    p.add_argument("-o", "--output", help="output file (default: strix-<name>)")
    p.add_argument(
        "-m",
        "--mode",
        type=int,
        choices=(1, 2, 3),
        default=2,
        help="mode (1=light, 2=full, 3=mega)",
    )
    p.add_argument(
        "--no-protect", action="store_true", help="disable anti-hook/anti-debug header"
    )
    p.add_argument("--no-hide", action="store_true", help="disable hide-builtins")
    p.add_argument(
        "--no-more",
        action="store_true",
        help="disable identifier renaming and extra control-flow passes",
    )
    p.add_argument(
        "--hw-bind",
        action="store_true",
        help="bind encrypted payload to current machine hardware fingerprint",
    )
    p.add_argument(
        "--py-lock",
        action="store_true",
        default=True,
        help="lock payload execution to current Python major.minor version (default)",
    )
    p.add_argument(
        "--no-py-lock",
        action="store_true",
        help="disable Python version lock",
    )
    p.add_argument(
        "--no-junk",
        action="store_true",
        help="disable opaque junk function injection",
    )
    p.add_argument(
        "--no-cff",
        action="store_true",
        help="disable top-level control-flow flattening",
    )
    p.add_argument("--no-anti-debug", action="store_true", help="disable anti-debug guard")
    p.add_argument("--no-anti-hook", action="store_true", help="disable anti-hook guard")
    p.add_argument("--no-anti-frame", action="store_true", help="disable anti-frame guard")
    p.add_argument("--no-anti-vm", action="store_true", help="disable anti-VM guard")
    p.add_argument("--no-anti-proxy", action="store_true", help="disable anti-proxy guard")
    p.add_argument(
        "--no-anti-httptoolkit", action="store_true", help="disable anti-HTTPToolkit guard"
    )
    p.add_argument("--no-anti-pydc", action="store_true", help="disable anti-decompiler traps")
    p.add_argument(
        "--no-anti-crack", action="store_true", help="disable anti-crack socket/builtin guard"
    )
    p.add_argument("--banner", action="store_true", help="show banner even with -f")
    p.add_argument(
        "--style",
        choices=["mine", "legacy"],
        default="mine",
        help="output style: mine (mineral) | legacy (classic)",
    )
    return p.parse_args()


def _write_atomic(source_file, output, content):
    src_path = Path(source_file).resolve()
    out_path = Path(output)
    if out_path.is_symlink():
        raise ValueError("Refusing to overwrite a symbolic link.")
    if src_path == out_path.resolve():
        raise ValueError("Output path must be different from the input source file.")
    out_dir = out_path.resolve().parent
    fd, tmp_name = tempfile.mkstemp(prefix=".strix-", suffix=".tmp", dir=str(out_dir))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        os.replace(tmp_name, out_path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def run_headless(
    file,
    output,
    mode,
    protect,
    hide,
    more,
    style="mine",
    *,
    importable=False,
    hw_bind=False,
    py_lock=True,
    anti_debug=True,
    anti_hook=True,
    anti_frame=True,
    anti_vm=True,
    anti_proxy=True,
    anti_httptoolkit=True,
    anti_pydc=True,
    anti_crack=True,
    junk=True,
    cff=True,
):
    src_path = Path(file).resolve()
    out_path = Path(output)
    if src_path.is_file():
        validate_output(src_path, out_path)
    if src_path.is_dir() or (
        src_path.suffix.lower() == ".java" and not out_path.parent.exists()
    ):
        events = queue.Queue()
        cancel = threading.Event()
        worker = threading.Thread(
            target=run_build,
            args=(
                BuildRequest(
                    src_path,
                    out_path,
                    mode,
                    style,
                    protect,
                    hide,
                    more,
                    hw_bind,
                    py_lock,
                ),
                events,
                cancel,
            ),
            daemon=True,
        )
        worker.start()
        processes = []
        try:
            while True:
                kind, value = events.get()
                if kind == "process":
                    processes.append(value)
                elif kind == "log":
                    log_event(value)
                elif kind == "error":
                    raise ValueError(value)
                elif kind == "done":
                    log_ok(f"Saved {value}")
                    return
                elif kind == "cancelled":
                    raise ValueError("Build cancelled.")
        finally:
            cancel.set()
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            worker.join()
    language = require_language(src_path)
    if out_path.is_symlink():
        raise ValueError("Refusing to overwrite a symbolic link.")
    if src_path == out_path.resolve():
        raise ValueError("Output path must be different from the input source file.")
    log_event(f"Loaded {file} | {language.name}")
    if language.engine != "python":
        log_info(
            "Python runtime guards, builtin hiding and naming style apply only to Python."
        )
    out = obfuscate_file(
        src_path,
        mode=mode,
        protect=protect,
        hide=hide,
        more=more,
        style=style,
        importable=importable,
        hw_bind=hw_bind,
        py_lock=py_lock,
        anti_debug=anti_debug,
        anti_hook=anti_hook,
        anti_frame=anti_frame,
        anti_vm=anti_vm,
        anti_proxy=anti_proxy,
        anti_httptoolkit=anti_httptoolkit,
        anti_pydc=anti_pydc,
        anti_crack=anti_crack,
        junk=junk,
        cff=cff,
    )
    _write_atomic(file, output, out)
    log_ok(f"Saved {output} | engine done.")


def main():
    args = parse_args()

    if args.list_languages:
        for language in LANGUAGES:
            suffixes = ", ".join(language.suffixes)
            output = f" -> {language.output_suffix}" if language.output_suffix else ""
            print(f"{language.name}: {suffixes}{output}")
        return

    if args.gui or (not args.file and not args.cli):
        from .gui import launch_gui

        launch_gui(
            initial_file=args.file,
            output=args.output,
            mode=args.mode,
            style=args.style,
            protect=not args.no_protect,
            hide=not args.no_hide,
            more=not args.no_more,
        )
        return

    if args.file:
        if args.banner:
            print_logo()
        output = args.output or str(default_output(Path(args.file)))
        protect = not args.no_protect
        hide = not args.no_hide
        more = not args.no_more
        mode = args.mode
        style = args.style
        st = time.time()
        try:
            run_headless(
                args.file,
                output,
                mode,
                protect,
                hide,
                more,
                style,
                importable=args.importable,
                hw_bind=args.hw_bind,
                py_lock=args.py_lock and not args.no_py_lock,
                anti_debug=not args.no_anti_debug,
                anti_hook=not args.no_anti_hook,
                anti_frame=not args.no_anti_frame,
                anti_vm=not args.no_anti_vm,
                anti_proxy=not args.no_anti_proxy,
                anti_httptoolkit=not args.no_anti_httptoolkit,
                anti_pydc=not args.no_anti_pydc,
                anti_crack=not args.no_anti_crack,
                junk=not args.no_junk,
                cff=not args.no_cff,
            )
            log_info(f"Done in {time.time() - st:.3f}s")
            return
        except Exception as e:  # noqa: BLE001 - report failures at the CLI boundary.
            log_warn(f"Engine error: {e}")
            traceback.print_exc()
            sys.exit(1)

    print_logo()
    print()
    file = (
        input(stage("Drag file into console then Enter: ", symbol="?"))
        .strip()
        .strip("\"'")
    )
    while True:
        try:
            read_source(Path(file))
            break
        except (OSError, UnicodeError, SyntaxError, ValueError):
            file = (
                input(stage("File not found, try again: ", symbol="?"))
                .strip()
                .strip("\"'")
            )

    while True:
        try:
            mode = int(input(stage("MODE (1=Light, 2=Full, 3=Mega): ", symbol="?")))
            if 1 <= mode <= 3:
                break
        except ValueError:
            pass

    more = input(stage("More obfuscation? (Y/n): ", symbol="?")).strip().upper() != "N"
    hide = input(stage("Hide builtins? (Y/n): ", symbol="?")).strip().upper() != "N"
    protect = (
        input(stage("Anti-hook / Anti-debug? (Y/n): ", symbol="?")).strip().upper()
        != "N"
    )

    output = input(
        stage("Output file name (leave blank for default): ", symbol="?")
    ).strip()
    if not output:
        output = str(default_output(Path(file)))

    print()
    log_event("Starting Strix engine...")
    stt = time.time()
    try:
        run_headless(file, output, mode, protect, hide, more)
        log_info(f">>> Done in {time.time() - stt:.3f}s")
    except Exception as e:  # noqa: BLE001 - report failures at the CLI boundary.
        log_warn(f"Engine error: {e}")
        traceback.print_exc()
        sys.exit(1)
