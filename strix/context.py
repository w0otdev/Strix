# Copyright (c) 2026 w0otdev (Strix modifications)
# Original work Copyright (c) ktn1703 (https://github.com/ktn1703/Neo)
# Licensed under the Apache License, Version 2.0.
# Modified by w0otdev: Modularized and rebranded under Strix.

import hashlib
import random
import sys

sys.setrecursionlimit(1 << 20)

if sys.version_info < (3, 10):  # noqa: UP036 - enforce the minimum version at startup.
    print("STRIX requires Python 3.10+")
    sys.exit(1)

VER = f"{sys.version_info.major}.{sys.version_info.minor}"

OFF = 0xFF78FF
K = random.randint(1, 0xFFFFFFFF)
DIE_CODE = 0xC0DE
INNER_NAME = "<Strix>"

KILL_MODULES = (
    "frida",
    "pydevd",
    "debugpy",
    "pyrasite",
    "lief",
    "ptvsd",
    "pycharm",
    "gdb",
    "pytineye",
    "yara",
    "sysmon",
    "trace",
    "coverage",
    "line_profiler",
)

MITM_TOKENS = (
    "httptoolkit",
    "fiddler",
    "burp",
    "charles",
    "zaproxy",
    "mitmproxy",
    "optimizely",
    "proxify",
    "vanguard",
)

HANZI = "天地玄黄宇宙洪荒日月盈昃辰宿列张金木水火土龙虎风云雷电山河星海"

BUILTINS = {
    "__import__",
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "breakpoint",
    "callable",
    "chr",
    "compile",
    "delattr",
    "dir",
    "divmod",
    "eval",
    "exec",
    "format",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "hex",
    "id",
    "input",
    "isinstance",
    "issubclass",
    "iter",
    "aiter",
    "len",
    "locals",
    "max",
    "min",
    "next",
    "anext",
    "oct",
    "ord",
    "pow",
    "print",
    "repr",
    "round",
    "setattr",
    "sorted",
    "sum",
    "vars",
    "None",
    "Ellipsis",
    "NotImplemented",
    "False",
    "True",
    "bool",
    "memoryview",
    "bytearray",
    "bytes",
    "classmethod",
    "complex",
    "dict",
    "enumerate",
    "filter",
    "float",
    "frozenset",
    "property",
    "int",
    "list",
    "map",
    "object",
    "range",
    "reversed",
    "set",
    "slice",
    "staticmethod",
    "str",
    "super",
    "tuple",
    "type",
    "zip",
    "open",
    "Exception",
    "KeyboardInterrupt",
    "MemoryError",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "ArithmeticError",
    "ZeroDivisionError",
    "NameError",
    "OverflowError",
    "NotImplementedError",
    "StopIteration",
    "assert",
}

HIDE_LIST = [
    "chr",
    "ord",
    "hex",
    "bin",
    "oct",
    "bytes",
    "bytearray",
    "str",
    "int",
    "float",
    "globals",
    "locals",
    "vars",
    "exec",
    "eval",
    "getattr",
    "setattr",
    "delattr",
    "dir",
    "__import__",
    "compile",
    "map",
    "filter",
    "zip",
    "hash",
    "repr",
    "format",
    "len",
    "range",
    "type",
    "print",
    "input",
    "open",
    "sorted",
    "sum",
    "abs",
    "min",
    "max",
    "next",
    "iter",
    "enumerate",
    "reversed",
    "isinstance",
    "issubclass",
    "hasattr",
    "callable",
    "super",
    "object",
    "staticmethod",
    "classmethod",
    "property",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "round",
    "pow",
    "divmod",
    "id",
    "slice",
]

MINERALS = [
    "bauxite",
    "apatite",
    "ilmenite",
    "monazite",
    "zircon",
    "cassiterite",
    "scheelite",
    "wolframite",
    "hematite",
    "magnetite",
    "galena",
    "sphalerite",
    "chalcopyrite",
    "cinnabar",
    "stibnite",
    "pyrolusite",
    "cryptomelane",
    "siderite",
    "smithsonite",
    "azurite",
    "malachite",
    "bornite",
    "realgar",
    "orpiment",
    "millerite",
    "pentlandite",
    "skutterudite",
    "vanadinite",
    "wulfenite",
    "anglesite",
    "cerussite",
    "brucite",
    "diaspore",
    "boehmite",
    "chromite",
    "columbite",
    "euclase",
    "magnesite",
    "kaolinite",
    "bentonite",
    "dolomite",
    "barite",
    "fluorite",
    "calcite",
    "gahnite",
    "annabergite",
    "manganite",
    "rhodochrosite",
    "stilbite",
    "lazurite",
    "aurichalcite",
]

NAME = {}


def reset_key():
    global K
    K = random.randint(1, 0xFFFFFFFF)
    return K


def rn(k=9):
    return "_" + "".join(
        random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=k)
    )


def QN(key):
    if key not in NAME:
        NAME[key] = rn()
    return NAME[key]


for _slot in (
    "dec",
    "int",
    "float",
    "bytes",
    "str",
    "chr",
    "join",
    "map",
    "list",
    "eval",
    "exec",
    "import",
    "vars",
    "globals",
    "getattr",
    "bd",
    "sysm",
    "osm",
    "mz",
    "lm",
    "bz",
    "b64",
    "ms",
    "die",
    "len",
    "hl",
):
    QN(_slot)


def hz():
    return "".join(random.choices(HANZI, k=random.randint(7, 9)))


def mkmarker():
    return "_STRIX_" + format(random.getrandbits(160), "040x") + "_"


def make_ks(data, need):
    out = b""
    n = 0
    while len(out) < need:
        out += hashlib.sha256(data + n.to_bytes(8, "big")).digest()
        n += 1
    return out[:need]


def splitnc(data, n):
    n = max(1, n)
    q_val, r_val = divmod(len(data), n)
    parts = []
    off = 0
    for i in range(n):
        s = q_val + (1 if i < r_val else 0)
        parts.append(data[off : off + s])
        off += s
    return parts


def enc_seq(s):
    return [(ord(c) ^ K) + OFF for c in s]


def q(s):
    return enc_seq(s)


def S(s):
    return f"{QN('dec')}({enc_seq(s)})"


def I(v):  # noqa: E743 - public integer-expression builder, paired with S/F/B.
    return f"{QN('int')}({S(str(v))})"


def I_(v):
    return I(v)


def F(v):
    return f"{QN('float')}({S(repr(v))})"


def B(v):
    if isinstance(v, bytes) and all(32 <= b < 127 for b in v):
        return f"{S(v.decode('ascii'))}.encode('ascii')"
    return None


class MINE:
    def __init__(self):
        self.pool = list(MINERALS)
        random.shuffle(self.pool)
        self.i = 0
        self.used = set()

    def n(self):
        while self.i < len(self.pool):
            c = self.pool[self.i]
            self.i += 1
            if c not in self.used:
                self.used.add(c)
                return c
        k = 0
        while True:
            c = f"lode_{k}"
            k += 1
            if c not in self.used:
                self.used.add(c)
                return c

    def nl(self):
        return "_" + self.n()


def _big():
    return random.randint(10**15, 9 * 10**16)


def alias_expr(T):
    kw = {"T": T}
    for k in "abcdefg":
        kw[k] = _big()
    return random.choice(
        [
            "({T}) if bool(type(int({a})>int({b})<int({c})>int({d}))) == bool(bool(str({e}) is not str({f}))) and bool(int({g})) < bool(type(None)) else {T}",
            "({T}) if bool(bool(bool(None))) < bool(type(str({a}))) or bool(int({b})) > bool(bool(str({c}))) else {T}",
            "({T}) if (bool(type(int({d}))) ^ bool(type(str({e})))) == bool(type(None)) and bool(int({f})) == bool(bool(None)) else {T}",
            "({T}) if bool(type(int({c}))) <= bool(type(int({d}))) and bool(str({e}) is not str({f})) < bool(type(None)) else {T}",
        ]
    ).format(**kw)
