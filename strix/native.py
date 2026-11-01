"""Compiler-backed source transformations for C/C++, C# and Java."""

import hashlib
import importlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from bisect import bisect_right
from pathlib import Path

ENGINE = Path(__file__).parent / "engines" / "native"
_BUILD_LOCK = threading.Lock()


def _run(command, *, cwd=None):
    result = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    if result.returncode:
        raise ValueError(result.stdout.strip())
    return result.stdout


def managed_command(path: Path, *, mode=2, more=True, output: Path | None = None):
    java = path.suffix.lower() == ".java"
    tool = shutil.which("javac" if java else "dotnet")
    runtime = shutil.which("java") if java else tool
    if not tool or not runtime:
        raise ValueError(
            "Java requires JDK 17+ (java and javac on PATH)."
            if java
            else "C# requires the .NET SDK 8+ on PATH."
        )
    version = _run([tool, "-version" if java else "--version"]).strip()
    sources = (
        [ENGINE / "StrixJava.java"]
        if java
        else [ENGINE / "csharp" / name for name in ("StrixNative.csproj", "Program.cs")]
    )
    digest = hashlib.sha256((version + tool).encode())
    for source in sources:
        digest.update(source.read_bytes())
    cache_root = (
        Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".cache")))
        / "Strix"
        / "native"
    )
    cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cache = cache_root / digest.hexdigest()[:24]
    artifact = cache / ("StrixJava.class" if java else "StrixNative.dll")
    with _BUILD_LOCK:
        if not artifact.is_file():
            # shortcut: first-use driver setup finishes before cancellation; add cancellable setup if SDK bootstrap becomes slow.
            with tempfile.TemporaryDirectory(
                prefix=".build-", dir=cache_root
            ) as folder:
                stage = Path(folder) / "driver"
                stage.mkdir()
                if java:
                    _run(
                        [
                            tool,
                            "-proc:none",
                            "-encoding",
                            "UTF-8",
                            "-d",
                            str(stage),
                            str(sources[0]),
                        ]
                    )
                else:
                    major = int(version.split(".")[0])
                    if major < 8:
                        raise ValueError("C# requires the .NET SDK 8+.")
                    _run(
                        [
                            tool,
                            "build",
                            str(sources[0]),
                            "--nologo",
                            "-v:q",
                            "-p:ImportDirectoryBuildProps=false",
                            "-p:ImportDirectoryBuildTargets=false",
                            "-o",
                            str(stage),
                            f"-p:StrixSdkMajor={major}",
                            f"-p:BaseIntermediateOutputPath={Path(folder) / 'obj'}/",
                        ],
                        cwd=ENGINE,
                    )
                try:
                    stage.rename(cache)
                except OSError:
                    if not artifact.is_file():
                        raise
    command = (
        [runtime, "-Dfile.encoding=UTF-8", "-cp", str(cache), "StrixJava"]
        if java
        else [runtime, str(artifact)]
    )
    command += [str(path.resolve()), str(mode), "1" if more else "0"]
    if output is not None:
        command.append(str(output.resolve()))
    return command


def _clang_args(path, cindex):
    flags = []
    for parent in path.parents:
        if (parent / "compile_commands.json").is_file():
            commands = cindex.CompilationDatabase.fromDirectory(
                str(parent)
            ).getCompileCommands(str(path))
            if commands:
                command = commands[0]
                flags.append("-working-directory=" + command.directory)
                arguments = iter(list(command.arguments)[1:])
                # shortcut: only parsing flags are imported; expand this whitelist when other compiler settings are needed.
                for arg in arguments:
                    if arg in (
                        "-I",
                        "-D",
                        "-U",
                        "-isystem",
                        "-iquote",
                        "-include",
                        "-imsvc",
                        "-isysroot",
                        "-resource-dir",
                    ):
                        value = next(arguments, None)
                        if value is None:
                            raise ValueError(
                                f"Missing compile_commands.json value for {arg}."
                            )
                        flags.extend((arg, value))
                    elif arg.startswith(
                        (
                            "-I",
                            "-D",
                            "-U",
                            "-std=",
                            "--target=",
                            "--sysroot=",
                            "-fms-compatibility-version=",
                        )
                    ) or arg in (
                        "-fms-extensions",
                        "-fms-compatibility",
                        "-m32",
                        "-m64",
                        "-pthread",
                        "-nostdinc",
                        "-nostdinc++",
                    ):
                        flags.append(arg)
                    elif arg in ("/I", "/D", "/U", "/FI"):
                        value = next(arguments, None)
                        if value is None:
                            raise ValueError(
                                f"Missing compile_commands.json value for {arg}."
                            )
                        flags.extend(
                            ("-include" if arg == "/FI" else "-" + arg[1:], value)
                        )
                    elif arg.startswith("/std:"):
                        standard = (
                            arg[5:]
                            .replace("c++latest", "c++2b")
                            .replace("clatest", "c2x")
                        )
                        flags.append("-std=" + standard)
                    elif arg.startswith(("/I", "/D", "/U")):
                        flags.append("-" + arg[1:])
                return flags
            break
    return flags


def _encode_c_string(spelling, mode):
    quote = spelling.find('"')
    prefix = spelling[:quote]
    # shortcut: raw strings and user-defined literal suffixes stay intact; extend with a value-aware decoder when needed.
    if (
        quote < 0
        or prefix not in ("", "u8", "u", "U", "L")
        or not spelling.endswith('"')
    ):
        return spelling
    body = spelling[quote + 1 : -1]
    parts = re.findall(
        r"\\(?:\r?\n|x[0-9a-fA-F]+|[0-7]{1,3}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)|[^\\]",
        body,
        re.DOTALL,
    )
    encoded = [
        f"\\{ord(part):03o}" if len(part) == 1 and 32 <= ord(part) < 127 else part
        for part in parts
    ]
    size = 8 if mode == 3 else max(1, len(encoded))
    chunks = [
        "".join(encoded[index : index + size]) for index in range(0, len(encoded), size)
    ] or [""]
    return " ".join(prefix + '"' + chunk + '"' for chunk in chunks)


def obfuscate_c(path: Path, *, mode=2, more=True):
    try:
        cindex = importlib.import_module("clang.cindex")
    except ImportError as error:
        raise ValueError(
            "C/C++ requires: python -m pip install -r requirements-native.txt"
        ) from error
    if os.environ.get("LIBCLANG_PATH") and not cindex.Config.loaded:
        cindex.Config.set_library_path(os.environ["LIBCLANG_PATH"])
    path = path.resolve()
    data = path.read_bytes()
    data.decode("utf-8-sig")  # Fail on unsupported encodings before writing any output.
    args = _clang_args(path, cindex)
    cpp = path.suffix.lower() not in (".c", ".h") or path.suffix == ".C"
    language = "c++" if cpp else "c"
    if not any(arg.startswith("-std=") for arg in args):
        args.append("-std=c++17" if cpp else "-std=c11")
    # libclang 18 understands these headers; the MSVC version gate otherwise rejects parsing.
    if sys.platform == "win32":
        args.append("-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH")
    index = cindex.Index.create()
    unit = index.parse(
        str(path),
        args=["-x", language, *args],
        options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
    )
    errors = [
        str(item)
        for item in unit.diagnostics
        if item.severity >= cindex.Diagnostic.Error
    ]
    if errors and path.suffix.lower() == ".h":
        args = [arg for arg in args if not arg.startswith("-std=")]
        unit = index.parse(
            str(path),
            args=["-x", "c++", "-std=c++17", *args],
            options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
        errors = [
            str(item)
            for item in unit.diagnostics
            if item.severity >= cindex.Diagnostic.Error
        ]
    if errors:
        raise ValueError(
            "C/C++ parsing failed. Supply include paths/defines via compile_commands.json.\n"
            + "\n".join(errors[:6])
        )
    tokens = list(unit.get_tokens(extent=unit.cursor.extent))
    kinds = cindex.CursorKind
    functions = {
        kinds.FUNCTION_DECL,
        kinds.CXX_METHOD,
        kinds.CONSTRUCTOR,
        kinds.DESTRUCTOR,
        kinds.FUNCTION_TEMPLATE,
    }
    macros = sorted(
        (node.extent.start.offset, node.extent.end.offset)
        for node in unit.cursor.get_children()
        if node.kind == kinds.MACRO_INSTANTIATION
        and node.location.file
        and Path(node.location.file.name) == path
    )
    merged = []
    for start, end in macros:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    macros = merged
    starts = [start for start, _ in macros]

    def in_macro(token):
        position = bisect_right(starts, token.extent.start.offset) - 1
        return position >= 0 and token.extent.start.offset < macros[position][1]

    candidates = {}
    bindings = {}
    for token in tokens:
        if token.kind != cindex.TokenKind.IDENTIFIER:
            continue
        cursor = token.cursor.referenced
        key = cursor.get_usr() if cursor else ""
        bindings[token.extent.start.offset] = key
        if (
            cursor
            and cursor.kind == kinds.VAR_DECL
            and cursor.semantic_parent.kind in functions
            and cursor.location.file
            and Path(cursor.location.file.name) == path
            and key
        ):
            candidates[key] = cursor.spelling
    # Any use hidden in macros or inactive branches keeps that name unchanged.
    blocked = {
        token.spelling
        for token in tokens
        if token.kind == cindex.TokenKind.IDENTIFIER
        and (not bindings.get(token.extent.start.offset) or in_macro(token))
    }
    names = {}
    used = {token.spelling for token in tokens}
    if more and mode >= 2:
        for key, name in candidates.items():
            if name not in blocked:
                renamed = "s" + secrets.token_hex(16 if mode == 3 else 8)
                while renamed in used:
                    renamed = "s" + secrets.token_hex(16)
                names[key] = renamed
                used.add(renamed)
    edits = []
    for token in tokens:
        start, end = token.extent.start.offset, token.extent.end.offset
        if token.kind == cindex.TokenKind.COMMENT:
            replacement = re.sub(rb"[^\r\n]", b" ", data[start:end])
        elif token.kind == cindex.TokenKind.IDENTIFIER and bindings.get(start) in names:
            replacement = names[bindings[start]].encode()
        elif (
            token.kind == cindex.TokenKind.LITERAL
            and token.cursor.kind == kinds.STRING_LITERAL
            and not in_macro(token)
        ):
            replacement = _encode_c_string(token.spelling, mode).encode("utf-8")
        else:
            continue
        edits.append((start, end, replacement))
    result = []
    position = 0
    for start, end, replacement in edits:
        result.extend((data[position:start], replacement))
        position = end
    result.append(data[position:])
    return b"".join(result).decode("utf-8-sig")
