"""Language detection and dispatch shared by the CLI and desktop app."""

import shutil
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path

from .runtime import pipeline

JS_ENGINE = Path(__file__).parent / "engines" / "javascript"


@dataclass(frozen=True)
class Language:
    name: str
    suffixes: tuple[str, ...]
    engine: str
    output_suffix: str | None = None


LANGUAGES = (
    Language("Python", (".py", ".pyw"), "python"),
    Language("JavaScript", (".js", ".mjs", ".cjs"), "javascript"),
    Language("TypeScript", (".ts",), "javascript", ".js"),
    Language("TypeScript ESM", (".mts",), "javascript", ".mjs"),
    Language("TypeScript CommonJS", (".cts",), "javascript", ".cjs"),
    Language("JSX / TSX", (".jsx", ".tsx"), "javascript", ".js"),
    Language("C", (".c",), "c"),
    Language("C++", (".cc", ".cpp", ".cxx", ".c++"), "c"),
    Language(
        "C/C++ headers",
        (".h", ".hh", ".hpp", ".hxx", ".h++"),
        "c",
    ),
    Language("C#", (".cs",), "csharp"),
    Language("Java", (".java",), "java"),
)
SUPPORTED_SUFFIXES = frozenset(suffix for item in LANGUAGES for suffix in item.suffixes)
PYTHON_SUFFIXES = frozenset((".py", ".pyw"))
FILE_TYPES = [
    (
        "Supported source",
        " ".join("*" + suffix for suffix in sorted(SUPPORTED_SUFFIXES)),
    ),
    *(
        (item.name, " ".join("*" + suffix for suffix in item.suffixes))
        for item in LANGUAGES
    ),
    ("All files", "*"),
]


def language_for(path: Path) -> Language | None:
    name = path.name.lower()
    if name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return None  # Type declarations have no executable code.
    return next(
        (item for item in LANGUAGES if path.suffix.lower() in item.suffixes), None
    )


def require_language(path: Path) -> Language:
    language = language_for(path)
    if language is None:
        raise ValueError(
            f"Unsupported source format: {path.name}. Supported: "
            + ", ".join(sorted(SUPPORTED_SUFFIXES))
            + ". Type declarations are copied only in project builds."
        )
    return language


def output_relative(path: Path) -> Path:
    language = language_for(path)
    return (
        path.with_suffix(language.output_suffix)
        if language and language.output_suffix
        else path
    )


def read_source(path: Path, *, limit: int = -1) -> str:
    require_language(path)
    if path.suffix.lower() in PYTHON_SUFFIXES:
        with tokenize.open(path) as stream:
            return stream.read(limit)
    with path.open(encoding="utf-8-sig") as stream:
        return stream.read(limit)


def validate_output(source: Path, output: Path):
    language = require_language(source)
    if output.suffix.lower() != output_relative(source).suffix.lower():
        raise ValueError(
            f"Use a {output_relative(source).suffix} output for {language.name}."
        )
    if language.engine == "java" and source.name != output.name:
        raise ValueError(
            "Java output must keep the original file name. Choose another folder."
        )


def obfuscate_file(
    path: Path,
    *,
    mode=2,
    protect=True,
    hide=True,
    more=True,
    style="mine",
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
) -> str:
    language = require_language(path)
    if mode not in (1, 2, 3):
        raise ValueError("Select mode 1, 2 or 3.")
    if language.engine == "python":
        return pipeline(
            read_source(path),
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
    if language.engine == "c":
        from .native import obfuscate_c

        return obfuscate_c(path, mode=mode, more=more)
    if language.engine in ("csharp", "java"):
        from .native import managed_command

        command = managed_command(path, mode=mode, more=more)
    else:
        command = javascript_command(path, mode=mode, more=more)
    result = subprocess.run(
        command,
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    if result.returncode:
        raise ValueError(f"{language.name} engine: {result.stderr.strip()}")
    return result.stdout


def javascript_command(
    path: Path, *, mode=2, more=True, output: Path | None = None
) -> list[str]:
    node = shutil.which("node")
    if not node:
        raise ValueError("JavaScript/TypeScript requires Node.js 18+ on PATH.")
    if any(
        not (JS_ENGINE / "node_modules" / name).is_dir()
        for name in ("javascript-obfuscator", "typescript")
    ):
        raise ValueError(
            "JavaScript engine dependencies are missing. Run: "
            f'npm ci --prefix "{JS_ENGINE}"'
        )
    command = [
        node,
        str(JS_ENGINE / "driver.cjs"),
        str(path.resolve()),
        str(mode),
        "1" if more else "0",
    ]
    if output is not None:
        command.append(str(output.resolve()))
    return command
