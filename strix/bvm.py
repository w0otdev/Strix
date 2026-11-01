"""Strix BVM — Custom Bytecode Virtualization & Poly-Opcode Engine.

Serializes Python ``types.CodeType`` trees into a custom binary format with:
- Per-build random 16-byte magic header, 4-byte version tag, 64-bit integer XOR key,
  and 8-bit rolling string/bytes XOR key (zero static signatures).
- Per-CodeType poly-opcode bijection over instruction start offsets.
- Per-CodeType 64-bit xorshift stream cipher over swapped bytecode.
- Recursive custom constant table covering all Python constant types including
  arbitrary-precision big integers without falling back to ``marshal`` for code or primitives.
"""

from __future__ import annotations

import dis
import marshal
import secrets
import struct
import sys
import types
import zlib
from typing import Any

# Constant type tags
_T_NONE = 0x00
_T_TRUE = 0x01
_T_FALSE = 0x02
_T_INT = 0x03
_T_FLOAT = 0x04
_T_STR = 0x05
_T_BYTES = 0x06
_T_TUPLE = 0x07
_T_CODE = 0x08
_T_MARSHAL = 0x09
_T_COMPLEX = 0x0A
_T_LIST = 0x0B
_T_SET = 0x0C
_T_FROZENSET = 0x0D
_T_DICT = 0x0E
_T_ELLIPSIS = 0x0F
_T_SLICE = 0x10
_T_BYTEARRAY = 0x11
_T_BIGINT = 0x12

_SKIP_OPS: frozenset[str] = frozenset({"CACHE", "COPY", "INTRINSIC_1", "INTRINSIC_2"})
_MASK64 = 0xFFFFFFFFFFFFFFFF
_INT64_MIN = -0x8000000000000000
_INT64_MAX = 0x7FFFFFFFFFFFFFFF


def new_bvm_meta() -> dict[str, Any]:
    """Generate fresh per-build random BVM metadata keys and headers."""
    return {
        "magic": secrets.token_bytes(16),
        "ver": secrets.token_bytes(4),
        "int_xor": secrets.randbits(64) | 1,
        "str_xor": secrets.randbelow(254) + 1,
    }


def _op_starts(co: types.CodeType) -> set[int]:
    """Collect instruction byte offsets eligible for poly-opcode permutation."""
    starts: set[int] = set()
    try:
        for ins in dis.Bytecode(co):
            # shortcut: >H caps permuted offsets at 65535 bytes per CodeType; upgrade to >I if >64KB functions need permutation
            if ins.opname not in _SKIP_OPS and 0 <= ins.offset <= 0xFFFF:
                starts.add(ins.offset)
    except Exception:
        pass
    return starts


def _make_op_bijection(
    raw: bytes, starts: set[int]
) -> tuple[dict[int, int], dict[int, int]]:
    """Create a collision-free bijection for all distinct opcode bytes at ``starts``."""
    used = sorted({raw[i] for i in starts if 0 <= i < len(raw) and 1 <= raw[i] <= 254})
    if not used:
        return {}, {}
    rng = secrets.SystemRandom()
    targets = rng.sample(range(1, 255), len(used))
    fwd = dict(zip(used, targets))
    rev = {v: k for k, v in fwd.items()}
    return fwd, rev


def _swap_ops(raw: bytes, starts: set[int], fwd: dict[int, int]) -> bytes:
    """Apply forward poly-opcode permutation at instruction start offsets."""
    out = bytearray(raw)
    for i in starts:
        if 0 <= i < len(out) and out[i] in fwd:
            out[i] = fwd[out[i]]
    return bytes(out)


def _restore_ops(data: bytes, starts: set[int], rev: dict[int, int]) -> bytes:
    """Restore original opcode bytes at instruction start offsets."""
    out = bytearray(data)
    for i in starts:
        if 0 <= i < len(out) and out[i] in rev:
            out[i] = rev[out[i]]
    return bytes(out)


def _scramble(data: bytes, seed: int) -> bytes:
    """Scramble/unscramble bytecode using a 64-bit xorshift stream cipher."""
    out = bytearray(len(data))
    x = (seed & _MASK64) or 0x5DEECE66D
    for i, b in enumerate(data):
        x ^= (x << 13) & _MASK64
        x ^= x >> 7
        x ^= (x << 17) & _MASK64
        out[i] = b ^ (x & 0xFF)
    return bytes(out)


_unscramble = _scramble


def _xor_rolling(data: bytes, str_xor: int) -> bytes:
    return bytes(b ^ ((str_xor + i) & 0xFF) for i, b in enumerate(data))


def _pack_str(s: str, str_xor: int = 0) -> bytes:
    raw = s.encode("utf-8", "surrogatepass")
    if str_xor:
        raw = _xor_rolling(raw, str_xor)
    return struct.pack(">I", len(raw)) + raw


def _unpack_str(data: bytes, pos: int, str_xor: int = 0) -> tuple[str, int]:
    (n,) = struct.unpack_from(">I", data, pos)
    pos += 4
    raw = data[pos : pos + n]
    if str_xor:
        raw = _xor_rolling(raw, str_xor)
    return raw.decode("utf-8", "surrogatepass"), pos + n


def _pack_bytes(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _unpack_bytes(data: bytes, pos: int) -> tuple[bytes, int]:
    (n,) = struct.unpack_from(">I", data, pos)
    pos += 4
    return data[pos : pos + n], pos + n


def _pack_str_tuple(t: tuple[str, ...], str_xor: int = 0) -> bytes:
    parts = [struct.pack(">I", len(t))]
    for s in t:
        parts.append(_pack_str(s, str_xor))
    return b"".join(parts)


def _unpack_str_tuple(
    data: bytes, pos: int, str_xor: int = 0
) -> tuple[tuple[str, ...], int]:
    (count,) = struct.unpack_from(">I", data, pos)
    pos += 4
    items: list[str] = []
    for _ in range(count):
        s, pos = _unpack_str(data, pos, str_xor)
        items.append(s)
    return tuple(items), pos


def pack_consts(
    consts: tuple[Any, ...] | list[Any],
    bvm_meta: dict[str, Any],
    inner_name: str | None = None,
) -> bytes:
    """Recursively serialize a sequence of constants into custom BVM format."""
    int_xor: int = bvm_meta["int_xor"] & _MASK64
    str_xor: int = bvm_meta["str_xor"] & 0xFF
    parts = [struct.pack(">I", len(consts))]

    for v in consts:
        if v is None:
            parts.append(bytes([_T_NONE]))
        elif v is True:
            parts.append(bytes([_T_TRUE]))
        elif v is False:
            parts.append(bytes([_T_FALSE]))
        elif v is Ellipsis:
            parts.append(bytes([_T_ELLIPSIS]))
        elif isinstance(v, int):
            if _INT64_MIN <= v <= _INT64_MAX:
                u = (v & _MASK64) ^ int_xor
                parts.append(bytes([_T_INT]) + struct.pack(">Q", u))
            else:
                sign = 1 if v < 0 else 0
                mag = abs(v)
                raw_mag = mag.to_bytes((mag.bit_length() + 7) // 8, "big")
                enc_mag = bytes(b ^ str_xor for b in raw_mag)
                parts.append(
                    bytes([_T_BIGINT, sign]) + struct.pack(">I", len(enc_mag)) + enc_mag
                )
        elif isinstance(v, float):
            parts.append(bytes([_T_FLOAT]) + struct.pack(">d", v))
        elif isinstance(v, complex):
            parts.append(bytes([_T_COMPLEX]) + struct.pack(">dd", v.real, v.imag))
        elif isinstance(v, str):
            raw = _xor_rolling(v.encode("utf-8", "surrogatepass"), str_xor)
            parts.append(bytes([_T_STR]) + _pack_bytes(raw))
        elif isinstance(v, bytes):
            raw = _xor_rolling(v, str_xor)
            parts.append(bytes([_T_BYTES]) + _pack_bytes(raw))
        elif isinstance(v, bytearray):
            raw = _xor_rolling(bytes(v), str_xor)
            parts.append(bytes([_T_BYTEARRAY]) + _pack_bytes(raw))
        elif isinstance(v, tuple):
            parts.append(bytes([_T_TUPLE]) + pack_consts(list(v), bvm_meta, inner_name))
        elif isinstance(v, list):
            parts.append(bytes([_T_LIST]) + pack_consts(v, bvm_meta, inner_name))
        elif isinstance(v, set):
            parts.append(bytes([_T_SET]) + pack_consts(list(v), bvm_meta, inner_name))
        elif isinstance(v, frozenset):
            parts.append(
                bytes([_T_FROZENSET]) + pack_consts(list(v), bvm_meta, inner_name)
            )
        elif isinstance(v, dict):
            keys = list(v.keys())
            vals = list(v.values())
            parts.append(
                bytes([_T_DICT])
                + struct.pack(">I", len(keys))
                + pack_consts(keys, bvm_meta, inner_name)
                + pack_consts(vals, bvm_meta, inner_name)
            )
        elif isinstance(v, slice):
            parts.append(
                bytes([_T_SLICE])
                + pack_consts([v.start, v.stop, v.step], bvm_meta, inner_name)
            )
        elif isinstance(v, types.CodeType):
            sub = pack_co(v, bvm_meta, inner_name)
            parts.append(bytes([_T_CODE]) + _pack_bytes(sub))
        else:
            raw = marshal.dumps(v)
            parts.append(bytes([_T_MARSHAL]) + _pack_bytes(raw))

    return b"".join(parts)


def unpack_consts(
    data: bytes, pos: int, bvm_meta: dict[str, Any]
) -> tuple[tuple[Any, ...], int]:
    """Recursively deserialize a BVM constant table starting at ``pos``."""
    int_xor: int = bvm_meta["int_xor"] & _MASK64
    str_xor: int = bvm_meta["str_xor"] & 0xFF
    (count,) = struct.unpack_from(">I", data, pos)
    pos += 4
    items: list[Any] = []

    for _ in range(count):
        tag = data[pos]
        pos += 1
        if tag == _T_NONE:
            items.append(None)
        elif tag == _T_TRUE:
            items.append(True)
        elif tag == _T_FALSE:
            items.append(False)
        elif tag == _T_ELLIPSIS:
            items.append(...)
        elif tag == _T_INT:
            (u,) = struct.unpack_from(">Q", data, pos)
            pos += 8
            u ^= int_xor
            val = u - 0x10000000000000000 if u >= 0x8000000000000000 else u
            items.append(val)
        elif tag == _T_BIGINT:
            sign = data[pos]
            pos += 1
            raw_mag, pos = _unpack_bytes(data, pos)
            mag = int.from_bytes(bytes(b ^ str_xor for b in raw_mag), "big")
            items.append(-mag if sign else mag)
        elif tag == _T_FLOAT:
            (val,) = struct.unpack_from(">d", data, pos)
            pos += 8
            items.append(val)
        elif tag == _T_COMPLEX:
            r, im = struct.unpack_from(">dd", data, pos)
            pos += 16
            items.append(complex(r, im))
        elif tag == _T_STR:
            raw, pos = _unpack_bytes(data, pos)
            s = _xor_rolling(raw, str_xor).decode("utf-8", "surrogatepass")
            items.append(s)
        elif tag == _T_BYTES:
            raw, pos = _unpack_bytes(data, pos)
            items.append(_xor_rolling(raw, str_xor))
        elif tag == _T_BYTEARRAY:
            raw, pos = _unpack_bytes(data, pos)
            items.append(bytearray(_xor_rolling(raw, str_xor)))
        elif tag == _T_TUPLE:
            sub_t, pos = unpack_consts(data, pos, bvm_meta)
            items.append(sub_t)
        elif tag == _T_LIST:
            sub_t, pos = unpack_consts(data, pos, bvm_meta)
            items.append(list(sub_t))
        elif tag == _T_SET:
            sub_t, pos = unpack_consts(data, pos, bvm_meta)
            items.append(set(sub_t))
        elif tag == _T_FROZENSET:
            sub_t, pos = unpack_consts(data, pos, bvm_meta)
            items.append(frozenset(sub_t))
        elif tag == _T_DICT:
            (_dc,) = struct.unpack_from(">I", data, pos)
            pos += 4
            keys, pos = unpack_consts(data, pos, bvm_meta)
            vals, pos = unpack_consts(data, pos, bvm_meta)
            items.append(dict(zip(keys, vals)))
        elif tag == _T_SLICE:
            sl, pos = unpack_consts(data, pos, bvm_meta)
            items.append(slice(sl[0], sl[1], sl[2]))
        elif tag == _T_CODE:
            sub_bytes, pos = _unpack_bytes(data, pos)
            co_obj, _ = rebuild_co(sub_bytes, 0, bvm_meta)
            items.append(co_obj)
        elif tag == _T_MARSHAL:
            raw, pos = _unpack_bytes(data, pos)
            items.append(marshal.loads(raw))
        else:
            raise ValueError(f"Unknown BVM constant tag: 0x{tag:02x}")

    return tuple(items), pos


def pack_co(
    co: types.CodeType,
    bvm_meta: dict[str, Any],
    inner_name: str | None = "<Strix>",
) -> bytes:
    """Recursively serialize a ``types.CodeType`` into BVM binary format."""
    str_xor: int = bvm_meta["str_xor"] & 0xFF
    seed = secrets.randbits(64) | 1
    raw_code = co.co_code
    starts = _op_starts(co)
    fwd, rev = _make_op_bijection(raw_code, starts)
    swapped = _swap_ops(raw_code, starts, fwd)
    scrambled = _scramble(swapped, seed)

    parts: list[bytes] = []
    parts.append(
        struct.pack(
            ">IIIIII",
            co.co_argcount,
            co.co_posonlyargcount,
            co.co_kwonlyargcount,
            co.co_nlocals,
            co.co_stacksize,
            co.co_flags,
        )
    )
    parts.append(struct.pack(">Q", seed))

    sorted_starts = sorted(starts)
    parts.append(struct.pack(">I", len(sorted_starts)))
    for s in sorted_starts:
        parts.append(struct.pack(">H", s))

    parts.append(struct.pack(">H", len(rev)))
    for k, v in rev.items():
        parts.append(struct.pack(">BB", k, v))

    parts.append(pack_consts(co.co_consts, bvm_meta, inner_name))
    parts.append(_pack_str_tuple(co.co_names, str_xor))
    parts.append(_pack_str_tuple(co.co_varnames, str_xor))
    parts.append(_pack_str_tuple(co.co_freevars, str_xor))
    parts.append(_pack_str_tuple(co.co_cellvars, str_xor))

    filename = inner_name if inner_name is not None else co.co_filename
    parts.append(_pack_str(filename, str_xor))
    parts.append(_pack_str(co.co_name, str_xor))
    qualname = getattr(co, "co_qualname", co.co_name)
    parts.append(_pack_str(qualname, str_xor))

    parts.append(struct.pack(">I", co.co_firstlineno))
    linetable = getattr(co, "co_linetable", b"") or b""
    parts.append(_pack_bytes(linetable))
    exctable = getattr(co, "co_exceptiontable", b"") or b""
    parts.append(_pack_bytes(exctable))
    parts.append(_pack_bytes(scrambled))

    return b"".join(parts)


def rebuild_co(
    data: bytes, pos: int, bvm_meta: dict[str, Any]
) -> tuple[types.CodeType, int]:
    """Reconstruct a ``types.CodeType`` tree from BVM binary format."""
    str_xor: int = bvm_meta["str_xor"] & 0xFF
    argcount, posonly, kwonly, nlocals, stacksize, flags = struct.unpack_from(
        ">IIIIII", data, pos
    )
    pos += 24
    (seed,) = struct.unpack_from(">Q", data, pos)
    pos += 8

    (n_starts,) = struct.unpack_from(">I", data, pos)
    pos += 4
    starts: set[int] = set()
    for _ in range(n_starts):
        (s,) = struct.unpack_from(">H", data, pos)
        pos += 2
        starts.add(s)

    (n_rev,) = struct.unpack_from(">H", data, pos)
    pos += 2
    rev: dict[int, int] = {}
    for _ in range(n_rev):
        k, v = struct.unpack_from(">BB", data, pos)
        pos += 2
        rev[k] = v

    consts, pos = unpack_consts(data, pos, bvm_meta)
    names, pos = _unpack_str_tuple(data, pos, str_xor)
    varnames, pos = _unpack_str_tuple(data, pos, str_xor)
    freevars, pos = _unpack_str_tuple(data, pos, str_xor)
    cellvars, pos = _unpack_str_tuple(data, pos, str_xor)
    filename, pos = _unpack_str(data, pos, str_xor)
    name, pos = _unpack_str(data, pos, str_xor)
    qualname, pos = _unpack_str(data, pos, str_xor)

    (firstlineno,) = struct.unpack_from(">I", data, pos)
    pos += 4
    linetable, pos = _unpack_bytes(data, pos)
    exctable, pos = _unpack_bytes(data, pos)
    scrambled, pos = _unpack_bytes(data, pos)

    unscrambled = _unscramble(scrambled, seed)
    raw_code = _restore_ops(unscrambled, starts, rev)

    if sys.version_info >= (3, 11):
        co = types.CodeType(
            argcount,
            posonly,
            kwonly,
            nlocals,
            stacksize,
            flags,
            raw_code,
            consts,
            names,
            varnames,
            filename,
            name,
            qualname,
            firstlineno,
            linetable,
            exctable,
            freevars,
            cellvars,
        )
    else:
        co = types.CodeType(
            argcount,
            posonly,
            kwonly,
            nlocals,
            stacksize,
            flags,
            raw_code,
            consts,
            names,
            varnames,
            filename,
            name,
            firstlineno,
            linetable,
            freevars,
            cellvars,
        )
    return co, pos


def build_bvm_package(
    source_or_code: str | bytes | types.CodeType,
    inner_name: str = "<Strix>",
    bvm_meta: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Compile and package source/CodeType into a compressed BVM payload."""
    if bvm_meta is None:
        bvm_meta = new_bvm_meta()
    if isinstance(source_or_code, types.CodeType):
        co = source_or_code
    else:
        co = compile(source_or_code, inner_name, "exec")

    try:
        body = bytes([_T_CODE]) + pack_co(co, bvm_meta, inner_name)
    except Exception:
        body = bytes([_T_MARSHAL]) + marshal.dumps(co)

    compressed = zlib.compress(body, 9)
    pkg = bvm_meta["magic"] + bvm_meta["ver"] + compressed
    return pkg, bvm_meta


def unpack_bvm_package(pkg: bytes, bvm_meta: dict[str, Any]) -> types.CodeType:
    """Verify headers, decompress, and reconstruct the root ``types.CodeType``."""
    magic: bytes = bvm_meta["magic"]
    ver: bytes = bvm_meta["ver"]
    m_len = len(magic)
    v_len = len(ver)
    if pkg[:m_len] != magic or pkg[m_len : m_len + v_len] != ver:
        raise ValueError("Invalid Strix BVM package header")
    body = zlib.decompress(pkg[m_len + v_len :])
    if body[0] == _T_MARSHAL:
        return marshal.loads(body[1:])
    if body[0] != _T_CODE:
        raise ValueError(f"Unexpected BVM root tag: 0x{body[0]:02x}")
    co, _ = rebuild_co(body, 1, bvm_meta)
    return co


def build_bvm_runner_src(
    bvm_meta: dict[str, Any], runner_name: str = "_StrixBVM"
) -> str:
    """Return compact self-contained Python source for the in-memory BVM loader."""
    magic_repr = repr(bytes(bvm_meta["magic"]))
    ver_repr = repr(bytes(bvm_meta["ver"]))
    int_xor_hex = hex(bvm_meta["int_xor"] & _MASK64)
    str_xor_hex = hex(bvm_meta["str_xor"] & 0xFF)

    return f"""def {runner_name}(_pkg, _g=None):
    import marshal as _m, struct as _st, sys as _sys, types as _ty, zlib as _zl
    _MG = {magic_repr}
    _VR = {ver_repr}
    _IX = {int_xor_hex}
    _SX = {str_xor_hex}
    _M64 = 0xFFFFFFFFFFFFFFFF
    if _pkg[:16] != _MG or _pkg[16:20] != _VR:
        raise RuntimeError("Corrupt payload")
    _bd = _zl.decompress(_pkg[20:])
    def _xr(_b):
        return bytes(_x ^ ((_SX + _i) & 0xFF) for _i, _x in enumerate(_b))
    def _ub(_d, _p):
        (_n,) = _st.unpack_from(">I", _d, _p)
        _p += 4
        return _d[_p:_p + _n], _p + _n
    def _us(_d, _p):
        _r, _p = _ub(_d, _p)
        return _xr(_r).decode("utf-8", "surrogatepass"), _p
    def _ust(_d, _p):
        (_c,) = _st.unpack_from(">I", _d, _p)
        _p += 4
        _o = []
        for _ in range(_c):
            _s, _p = _us(_d, _p)
            _o.append(_s)
        return tuple(_o), _p
    def _uc(_d, _p):
        (_c,) = _st.unpack_from(">I", _d, _p)
        _p += 4
        _o = []
        for _ in range(_c):
            _t = _d[_p]
            _p += 1
            if _t == 0:
                _o.append(None)
            elif _t == 1:
                _o.append(True)
            elif _t == 2:
                _o.append(False)
            elif _t == 15:
                _o.append(...)
            elif _t == 3:
                (_u,) = _st.unpack_from(">Q", _d, _p)
                _p += 8
                _u ^= _IX
                _o.append(_u - 0x10000000000000000 if _u >= 0x8000000000000000 else _u)
            elif _t == 18:
                _sg = _d[_p]
                _p += 1
                _rm, _p = _ub(_d, _p)
                _mg = int.from_bytes(bytes(_b ^ _SX for _b in _rm), "big")
                _o.append(-_mg if _sg else _mg)
            elif _t == 4:
                (_v,) = _st.unpack_from(">d", _d, _p)
                _p += 8
                _o.append(_v)
            elif _t == 10:
                _r, _im = _st.unpack_from(">dd", _d, _p)
                _p += 16
                _o.append(complex(_r, _im))
            elif _t == 5:
                _s, _p = _us(_d, _p)
                _o.append(_s)
            elif _t == 6:
                _r, _p = _ub(_d, _p)
                _o.append(_xr(_r))
            elif _t == 17:
                _r, _p = _ub(_d, _p)
                _o.append(bytearray(_xr(_r)))
            elif _t == 7:
                _sub, _p = _uc(_d, _p)
                _o.append(_sub)
            elif _t == 11:
                _sub, _p = _uc(_d, _p)
                _o.append(list(_sub))
            elif _t == 12:
                _sub, _p = _uc(_d, _p)
                _o.append(set(_sub))
            elif _t == 13:
                _sub, _p = _uc(_d, _p)
                _o.append(frozenset(_sub))
            elif _t == 14:
                (_dc,) = _st.unpack_from(">I", _d, _p)
                _p += 4
                _ks, _p = _uc(_d, _p)
                _vs, _p = _uc(_d, _p)
                _o.append(dict(zip(_ks, _vs)))
            elif _t == 16:
                _sl, _p = _uc(_d, _p)
                _o.append(slice(_sl[0], _sl[1], _sl[2]))
            elif _t == 8:
                _sb, _p = _ub(_d, _p)
                _co, _ = _rco(_sb, 0)
                _o.append(_co)
            elif _t == 9:
                _r, _p = _ub(_d, _p)
                _o.append(_m.loads(_r))
        return tuple(_o), _p
    def _rco(_d, _p):
        _ac, _po, _kw, _nl, _ss, _fl = _st.unpack_from(">IIIIII", _d, _p)
        _p += 24
        (_sd,) = _st.unpack_from(">Q", _d, _p)
        _p += 8
        (_ns,) = _st.unpack_from(">I", _d, _p)
        _p += 4
        _sts = set()
        for _ in range(_ns):
            (_s,) = _st.unpack_from(">H", _d, _p)
            _p += 2
            _sts.add(_s)
        (_nr,) = _st.unpack_from(">H", _d, _p)
        _p += 2
        _rv = {{}}
        for _ in range(_nr):
            _k, _v = _st.unpack_from(">BB", _d, _p)
            _p += 2
            _rv[_k] = _v
        _cs, _p = _uc(_d, _p)
        _nm, _p = _ust(_d, _p)
        _vn, _p = _ust(_d, _p)
        _fv, _p = _ust(_d, _p)
        _cv, _p = _ust(_d, _p)
        _fn, _p = _us(_d, _p)
        _cn, _p = _us(_d, _p)
        _qn, _p = _us(_d, _p)
        (_fln,) = _st.unpack_from(">I", _d, _p)
        _p += 4
        _lt, _p = _ub(_d, _p)
        _et, _p = _ub(_d, _p)
        _sc, _p = _ub(_d, _p)
        _ba = bytearray(len(_sc))
        _x = (_sd & _M64) or 0x5DEECE66D
        for _i, _b in enumerate(_sc):
            _x ^= (_x << 13) & _M64
            _x ^= _x >> 7
            _x ^= (_x << 17) & _M64
            _ba[_i] = _b ^ (_x & 0xFF)
        for _i in _sts:
            if 0 <= _i < len(_ba) and _ba[_i] in _rv:
                _ba[_i] = _rv[_ba[_i]]
        _rc = bytes(_ba)
        if _sys.version_info >= (3, 11):
            return _ty.CodeType(_ac, _po, _kw, _nl, _ss, _fl, _rc, _cs, _nm, _vn, _fn, _cn, _qn, _fln, _lt, _et, _fv, _cv), _p
        return _ty.CodeType(_ac, _po, _kw, _nl, _ss, _fl, _rc, _cs, _nm, _vn, _fn, _cn, _fln, _lt, _fv, _cv), _p
    _co = _m.loads(_bd[1:]) if _bd[0] == 9 else _rco(_bd, 1)[0]
    if _g is None:
        return _co
    exec(_co, _g)
    return _g
"""
