# Copyright (c) 2026 w0otdev (Strix modifications)
# Original work Copyright (c) ktn1703 (https://github.com/ktn1703/Neo)
# Licensed under the Apache License, Version 2.0.
# Modified by w0otdev: Modularized and rebranded under Strix.

import argparse
import sys
import time
import tokenize
import traceback
from pathlib import Path

from .context import VER
from .runtime import pipeline

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
    p.add_argument("-f", "--file", help="path to the file to obfuscate")
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
        help="disable variable renaming and advanced spam",
    )
    p.add_argument("--banner", action="store_true", help="show banner even with -f")
    p.add_argument(
        "--style",
        choices=["mine", "legacy"],
        default="mine",
        help="output style: mine (mineral) | legacy (classic)",
    )
    return p.parse_args()


def run_headless(
    file, output, mode, protect, hide, more, style="mine", *, importable=False
):
    with tokenize.open(file) as f:
        source = f.read()
    log_event(f"Loaded {file} ({len(source)} bytes)")
    out = pipeline(
        source,
        mode=mode,
        protect=protect,
        hide=hide,
        more=more,
        style=style,
        importable=importable,
    )
    with open(output, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    log_ok(f"Saved {output} | engine done.")


def main():
    args = parse_args()

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
        output = args.output or str(
            Path(args.file).with_name("strix-" + Path(args.file).name)
        )
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
        .replace('"', "")
        .replace("'", "")
        .strip()
    )
    while True:
        try:
            with open(file, encoding="utf-8-sig") as f:
                source = f.read()
            break
        except FileNotFoundError:
            file = (
                input(stage("File not found, try again: ", symbol="?"))
                .replace('"', "")
                .replace("'", "")
                .strip()
            )

    while True:
        try:
            mode = int(input(stage("MODE (1=Light, 2=Full, 3=Mega): ", symbol="?")))
            if 1 <= mode <= 3:
                break
        except ValueError:
            pass

    more = input(stage("More obfuscation? (y/N): ", symbol="?")).strip().upper() == "Y"
    hide = input(stage("Hide builtins? (Y/n): ", symbol="?")).strip().upper() != "N"
    protect = (
        input(stage("Anti-hook / Anti-debug? (Y/n): ", symbol="?")).strip().upper()
        != "N"
    )

    output = input(
        stage("Output file name (leave blank for default): ", symbol="?")
    ).strip()
    if not output:
        output = str(Path(file).with_name("strix-" + Path(file).name))

    print()
    log_event("Starting Strix engine...")
    stt = time.time()
    try:
        out = pipeline(source, mode=mode, protect=protect, hide=hide, more=more)
        with open(output, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
        log_ok(f"Saved {output}")
        log_info(f">>> Done in {time.time() - stt:.3f}s")
    except Exception as e:  # noqa: BLE001 - report failures at the CLI boundary.
        log_warn(f"Engine error: {e}")
        traceback.print_exc()
        sys.exit(1)
