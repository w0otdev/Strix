# Copyright (c) 2026 w0otdev (Strix modifications)
# Original work Copyright (c) ktn1703 (https://github.com/ktn1703/Neo)
# Licensed under the Apache License, Version 2.0.
# Modified by w0otdev: Modularized and rebranded under Strix.

import ast
import base64
import bz2
import lzma
import marshal
import sys
import zlib

from . import context as ctx
from .context import (
    DIE_CODE,
    INNER_NAME,
    KILL_MODULES,
    MINE,
    OFF,
    QN,
    VER,
    I,
    S,
    alias_expr,
    enc_seq,
    make_ks,
    mkmarker,
    q,
    rn,
)
from .literals import harden_literals
from .transforms import (
    Cv,
    anti_pycdc_block,
    clean_try_except,
    hide_builtins,
    obf_consts,
    obf_vars,
    spam,
)


def build_antidump():
    ga = QN("getattr")
    sm = QN("sysm")
    bd = QN("bd")
    ms = QN("ms")
    osm = QN("osm")
    die = QN("die")

    def T(v):
        return f"{bd}[{S(v)}]"

    bs = S("\\")
    sl = S("/")
    ln = rn()
    L = []
    a = L.append

    a(f"for _n_ in ({', '.join(S(x) for x in KILL_MODULES)}):")
    a(f"    if _n_ in {ga}({sm}, {S('modules')}): {die}()")
    a(
        f"for _en_ in ({', '.join(S(x) for x in (S('PYTHONBREAKPOINT'), S('PYTHONPYCACHEPREFIX')))}):"
    )
    a(f"    if {S('breakpoint')} in {osm}.environ.get(_en_, {S('')}).lower(): {die}()")
    a("try:")
    a(f"    _m_ = {ga}({sm}, {S('monitoring')})")
    a(f"    _ev_ = {ga}(_m_, {S('get_events')})()")
    a("    for _tid_ in _ev_:")
    a(f"        if _ev_[_tid_]: {die}()")
    a("except Exception:")
    a("    pass")
    a("try:")
    a(
        f"    if {T('type')}({ga}({ms}, {S('loads')})) != {T('type')}({T('len')}): {die}()"
    )
    a(
        f"    if {T('type')}({ga}({ms}, {S('loads')})) != {T('type')}({ga}({ms}, {S('dumps')})): {die}()"
    )
    a(
        f"    if {T('type')}({ga}({ms}, {S('load')})) != {T('type')}({ga}({ms}, {S('dumps')})): {die}()"
    )
    a(
        f"    if {T('type')}({ga}({ms}, {S('dump')})) != {T('type')}({T('len')}): {die}()"
    )
    a(f"except Exception: {die}()")
    a(f"if {T('type')}({T('compile')}) != {T('type')}({T('len')}): {die}()")
    a(f"if {T('type')}({T('__import__')}) != {T('type')}({T('len')}): {die}()")
    a(
        f"if {T('type')}({ga}({sm}, {S('gettrace')})) != {T('type')}({T('len')}): {die}()"
    )
    a(
        f"if {T('type')}({ga}({sm}, {S('setprofile')})) != {T('type')}({T('len')}): {die}()"
    )
    a("try:")
    a(
        f"    _fk_ = {T('getattr')}({T('__import__')}({S('types')}), {S('ModuleType')})({S('marshal')})"
    )
    a(f"    for _at_ in ({S('loads')}, {S('dumps')}, {S('load')}, {S('dump')}):")
    a(f"        {T('setattr')}(_fk_, _at_, (lambda *_v_: {die}()))")
    a(f"    {ga}({sm}, {S('modules')})[{S('marshal')}] = _fk_")
    a(f"except Exception: {die}()")
    a(f"def {ln}():")
    a(f"    _me_ = {ga}(({QN('globals')})(), {S('get')})({S('__file__')}, {S('')})")
    a(
        f"    _me_ = {ga}({ga}(_me_, {S('replace')})({bs}, {sl}), {S('rsplit')})({sl}, 1)[-1]"
    )
    a(f"    _af_ = {ga}({sm}, {S('argv')})[0] if {ga}({sm}, {S('argv')}) else {S('')}")
    a(
        f"    _af_ = {ga}({ga}(_af_, {S('replace')})({bs}, {sl}), {S('rsplit')})({sl}, 1)[-1]"
    )
    a(f"    if _me_ != _af_: {die}()")
    a(f"    _f_ = {ga}({sm}, {S('_getframe')})()")
    a("    while _f_ is not None:")
    a(f"        _c_ = {ga}({ga}(_f_, {S('f_code')}), {S('co_filename')}) or {S('')}")
    a(
        f"        _c_ = {ga}({ga}(_c_, {S('replace')})({bs}, {sl}), {S('rsplit')})({sl}, 1)[-1]"
    )
    a(f"        if _c_ != _me_ and _c_ != {S(INNER_NAME)}: {die}()")
    a(f"        _f_ = {ga}(_f_, {S('f_back')})")
    a(f"{ln}()")
    return "\n".join(L)


def build_guard():
    return (
        build_antidump()
        + "\n"
        + (
            f"if {QN('getattr')}({QN('sysm')},{S('gettrace')})() is not None:\n"
            f"    {QN('die')}()\n"
            f"{QN('getattr')}({QN('sysm')},{S('settrace')})(None)\n"
            f"try:\n"
            f"    {QN('getattr')}({QN('sysm')},{S('setprofile')})(None)\n"
            f"    if {QN('getattr')}({QN('getattr')}({QN('sysm')},{S('monitoring')}),{S('get_events')})():\n"
            f"        {QN('die')}()\n"
            f"except Exception:\n"
            f"    pass\n"
        )
    )


def build_antihook():
    return (
        f"if {QN('getattr')}({QN('sysm')}, {S('gettrace')})() is not None: {QN('die')}()\n"
        f"{QN('getattr')}({QN('sysm')}, {S('settrace')})(None)\n"
        f"{QN('getattr')}({QN('sysm')}, {S('setprofile')})(None)\n"
        f"try:\n"
        f"    if {QN('getattr')}({QN('getattr')}({QN('sysm')},{S('monitoring')}),{S('get_events')})():\n"
        f"        {QN('die')}()\n"
        f"except Exception:\n"
        f"    pass\n"
        f"for _n_ in ({', '.join(S(x) for x in KILL_MODULES)}):\n"
        f"    if _n_ in {QN('sysm')}.modules: {QN('die')}()\n"
    )


def build_runtime_legacy(compiled, protect=True):
    m1 = mkmarker()
    m2 = mkmarker()
    m1h = m1.encode().hex()
    m2h = m2.encode().hex()

    la = []
    a = la.append

    a("# -*- coding: utf-8 -*-")
    a(f"import sys as {QN('sysm')}")
    a(
        f"{QN('bd')} = (lambda _bx_: _bx_ if isinstance(_bx_, dict) else vars(_bx_))(globals()['__builtins__'])"
    )
    a(f"{QN('getattr')} = {QN('bd')}['getattr']")
    a(f"{QN('str')} = {QN('bd')}['str']")
    a(f"{QN('chr')} = {QN('bd')}['chr']")
    a(f"{QN('join')} = {QN('getattr')}({QN('str')}(), 'join')")
    a(f"{QN('int')} = {QN('bd')}['int']")
    a(f"{QN('len')} = {QN('bd')}['len']")
    a(f"{QN('float')} = {QN('bd')}['float']")
    a(f"{QN('bytes')} = {QN('bd')}['bytes']")
    a(f"{QN('list')} = {QN('bd')}['list']")
    a(f"{QN('map')} = {QN('bd')}['map']")
    a(f"{QN('eval')} = {QN('bd')}['eval']")
    a(f"{QN('exec')} = {QN('bd')}['exec']")
    a(f"{QN('import')} = {QN('bd')}['__import__']")
    a(f"{QN('vars')} = {QN('bd')}['vars']")
    a(f"{QN('globals')} = {QN('bd')}['globals']")
    a(
        f"{QN('dec')} = (lambda {QN('join')},{QN('chr')},_k_,_o_: (lambda _s_: {QN('join')}({QN('chr')}(((_x_ - _o_) ^ _k_)) for _x_ in _s_)))({QN('join')},{QN('chr')},{ctx.K},{OFF})"
    )

    a(f"def {QN('die')}():")
    a(f"    raise ({QN('bd')}[{S('SystemExit')}])({I(DIE_CODE)}) from None")

    a(
        f"_vv_ = {QN('getattr')}({QN('getattr')}({QN('sysm')}, {S('version_info')}), {S('major')})"
    )
    a(
        f"_w_ = {QN('getattr')}({QN('getattr')}({QN('sysm')}, {S('version_info')}), {S('minor')})"
    )
    a(f"if _vv_ != {I(sys.version_info.major)} or _w_ != {I(sys.version_info.minor)}:")
    a(f"    {QN('die')}()")

    a(f"{QN('osm')} = {QN('import')}({S('os')})")
    a(f"{QN('mz')} = {QN('import')}({S('zlib')})")
    a(f"{QN('lm')} = {QN('import')}({S('lzma')})")
    a(f"{QN('bz')} = {QN('import')}({S('bz2')})")
    a(f"{QN('b64')} = {QN('import')}({S('base64')})")
    a(f"{QN('ms')} = {QN('import')}({S('marshal')})")
    a(f"{QN('hl')} = {QN('import')}({S('hashlib')})")

    if protect:
        a(
            f"if {QN('getattr')}({QN('sysm')}, {S('gettrace')})() is not None: {QN('die')}()"
        )
        a(f"{QN('getattr')}({QN('sysm')}, {S('settrace')})(None)")
        a(f"{QN('getattr')}({QN('sysm')}, {S('setprofile')})(None)")
        a(
            f"for _n_ in ({S('frida')}, {S('pydevd')}, {S('debugpy')}, {S('pyrasite')}, {S('lief')}, {S('ptvsd')}, {S('pycharm')}, {S('gdb')}):"
        )
        a(f"    if _n_ in {QN('sysm')}.modules: {QN('die')}()")
        a(
            f"for _e_ in ({S('HTTP_PROXY')}, {S('HTTPS_PROXY')}, {S('http_proxy')}, {S('https_proxy')}):"
        )
        a(
            f"    if {S('127.0.0.1')} in {QN('osm')}.environ.get(_e_, {S('')}): {QN('die')}()"
        )
        a(
            f"for _t_ in ({S('HTTP_TOOLKIT_ACTIVE')}, {S('SSL_CERT_FILE')}, {S('NODE_EXTRA_CA_CERTS')}):"
        )
        a(
            f"    if {S('httptoolkit')} in {QN('osm')}.environ.get(_t_, {S('')}): {QN('die')}()"
        )
        a(
            f"if {QN('bd')}[{S('type')}]({QN('getattr')}({QN('ms')}, {S('loads')})) != {QN('bd')}[{S('type')}]({QN('bd')}[{S('len')}]): {QN('die')}()"
        )
        a(build_antidump())

    A = "\n".join(la)

    lc = []
    ca = lc.append
    ca("try:")
    ca(
        f"    with {QN('bd')}[{S('open')}]({QN('globals')}()[{S('__file__')}], {S('rb')}) as _src_:"
    )
    ca(f"        _ow_ = {QN('getattr')}(_src_, {S('read')})()")
    ca(
        f"    _i1_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m1h)}))"
    )
    ca(
        f"    _i2_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m2h)}), _i1_ + {I(len(m1))})"
    )
    ca(f"    _mt_ = _ow_[:_i1_] + _ow_[_i2_ + {I(len(m2))}:]")
    ca(f"    _A_ = {QN('getattr')}({QN('bz')}, {S('decompress')})(_pp_)")
    ca(f"    _B_ = {QN('getattr')}({QN('lm')}, {S('decompress')})(_A_)")
    ca(f"    _C_ = {QN('getattr')}({QN('mz')}, {S('decompress')})(_B_)")
    ca(f"    _D_ = {QN('getattr')}({QN('b64')}, {S('b85decode')})(_C_)")
    ca(f"    _Kq_ = {QN('bytes')}()")
    ca(f"    _nn_ = {I(0)}")
    ca(f"    while {QN('len')}(_Kq_) < {QN('len')}(_D_):")
    ca(
        f"        _Kq_ += {QN('getattr')}({QN('hl')}, {S('sha256')})(_mt_ + {QN('getattr')}({QN('int')}(_nn_), {S('to_bytes')})(8, {S('big')})).digest()"
    )
    ca(f"        _nn_ = _nn_ + {I(1)}")
    ca(f"    _E_ = {QN('bytes')}([(_b_ ^ _Kq_[_iX_]) for _iX_, _b_ in enumerate(_D_)])")
    ca(f"    _F_ = {QN('getattr')}({QN('ms')}, {S('loads')})(_E_)")
    ca("except Exception:")
    ca(f"    {QN('die')}()")
    ca("")
    ca("del _ow_, _mt_, _Kq_, _nn_, _pp_, _A_, _B_, _C_, _D_, _E_")
    ca(f"{QN('exec')}(_F_, {QN('globals')}())")
    C = "\n".join(lc)

    material = "#!/usr/bin/python" + VER + "\n" + A + "\n# \n" + C + "\n"
    ks = make_ks(material.encode("utf-8"), len(compiled))
    xored = bytes(a ^ b for a, b in zip(compiled, ks, strict=True))
    s85 = base64.b85encode(xored)
    z1 = zlib.compress(s85)
    z2 = lzma.compress(z1)
    z3 = bz2.compress(z2)

    chunk = 1500
    parts = [z3[i : i + chunk] for i in range(0, len(z3), chunk)]

    pnames = []
    for _ in parts:
        pname = rn()
        pnames.append(pname)

    refs = []
    for pname in pnames:
        refs.append(
            f"{QN('getattr')}({pname} , {S('to_bytes')})(({QN('getattr')}({pname} , {S('bit_length')})() + 7) // 8, {S('big')})[1:]"
        )

    pc = "\n".join(
        f"{pname} = {int.from_bytes(bytes([1]) + part, 'big')}"
        for pname, part in zip(pnames, parts, strict=True)
    )
    pp = f"_pp_ = {QN('getattr')}({QN('bytes')}(), {S('join')})([{', '.join(refs)}])"
    return "\n".join([*la, "# " + m1, pc, pp, "# " + m2, *lc])


def build_runtime(compiled, protect=True, *, importable=False):
    m1 = mkmarker()
    m2 = mkmarker()
    m1h = m1.encode().hex()
    m2h = m2.encode().hex()

    la = []
    a = la.append
    mine = MINE()

    lock = (
        f"_vv_=__import__('sys').version_info\n"
        f"if _vv_.major!={sys.version_info.major} or _vv_.minor!={sys.version_info.minor}:\n"
        f"    raise SystemExit({DIE_CODE})\n"
        f"del _vv_\n"
    )
    dec_expr = (
        '"".join(map(lambda _m_: chr((_m_ - '
        + str(OFF)
        + ") ^ "
        + str(ctx.K)
        + "), "
        + repr(enc_seq(lock))
        + "))"
    )
    a("# -*- coding: utf-8 -*-")
    a(f'__import__("builtins").exec({dec_expr})')

    sysa = mine.n()
    a(f"import sys as {sysa}")

    bm = {}
    for k in (
        "str",
        "int",
        "float",
        "bytes",
        "list",
        "map",
        "chr",
        "eval",
        "exec",
        "getattr",
        "vars",
        "globals",
        "type",
        "len",
        "__import__",
        "dict",
    ):
        nm = mine.n()
        bm[k] = nm
        a(f"globals()['{nm}'] = {alias_expr(k)}")

    deca = mine.n()
    a(
        f"({deca}) = (lambda _j_,_c_,_k_,_o_:(lambda _s_:_j_(_c_(((_x_-_o_)^_k_)) for _x_ in _s_)))(({bm['str']})().join,({bm['chr']}),{ctx.K},{OFF})"
    )
    d = deca
    g = bm["getattr"]

    for mk in ("os", "zlib", "lzma", "bz2", "base64", "marshal", "hashlib"):
        nm = mine.n()
        bm[mk] = nm
        a(f"({nm}) = ({bm['__import__']})(({d})({q(mk)}))")

    dnm = mine.n()
    a(f"def {dnm}():")
    a(f"    raise (SystemExit)(({bm['int']})(({d})({q(str(DIE_CODE))}))) from None")

    bdname = mine.n()
    a(
        f"({bdname}) = (lambda _bx_: _bx_ if isinstance(_bx_, dict) else vars(_bx_))(globals()['__builtins__'])"
    )
    jnm = mine.n()
    a(f"({jnm}) = ({bm['str']})().join")
    bridge = {
        "bd": bdname,
        "sysm": sysa,
        "osm": bm["os"],
        "mz": bm["zlib"],
        "lm": bm["lzma"],
        "bz": bm["bz2"],
        "b64": bm["base64"],
        "ms": bm["marshal"],
        "hl": bm["hashlib"],
        "dec": deca,
        "die": dnm,
        "getattr": bm["getattr"],
        "str": bm["str"],
        "chr": bm["chr"],
        "join": jnm,
        "int": bm["int"],
        "float": bm["float"],
        "bytes": bm["bytes"],
        "list": bm["list"],
        "map": bm["map"],
        "len": bm["len"],
        "eval": bm["eval"],
        "exec": bm["exec"],
        "import": bm["__import__"],
        "vars": bm["vars"],
        "globals": bm["globals"],
    }
    for _k, _v in bridge.items():
        a(f"globals()['{QN(_k)}'] = ({_v})")

    if protect:
        a(f"if ({g})(({sysa}),({d})({q('gettrace')}))() is not None: ({dnm})()")
        a(f"({g})(({sysa}),({d})({q('settrace')}))(None)")
        a(f"({g})(({sysa}),({d})({q('setprofile')}))(None)")
        bads = ",".join(
            f"({d})({q(x)})"
            for x in (
                "frida",
                "pydevd",
                "debugpy",
                "pyrasite",
                "lief",
                "ptvsd",
                "pycharm",
                "gdb",
            )
        )
        a(f"for _n_ in {bads}:")
        a(f"    if _n_ in ({g})(({sysa}),({d})({q('modules')})): ({dnm})()")
        evs = ",".join(
            f"({d})({q(x)})"
            for x in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
        )
        a(f"for _e_ in {evs}:")
        a(
            f"    if ({d})({q('127.0.0.1')}) in ({g})(({bm['os']}),({d})({q('environ')})).get(_e_,({d})([])): ({dnm})()"
        )
        evs2 = ",".join(
            f"({d})({q(x)})"
            for x in ("HTTP_TOOLKIT_ACTIVE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS")
        )
        a(f"for _t_ in {evs2}:")
        a(
            f"    if ({d})({q('httptoolkit')}) in ({g})(({bm['os']}),({d})({q('environ')})).get(_t_,({d})([])): ({dnm})()"
        )
        a(
            f"if ({bm['type']})(({g})(({bm['marshal']}),({d})({q('loads')}))) != ({bm['type']})(({bm['len']})): ({dnm})()"
        )
        a(build_antidump())

    A = "\n".join(la)
    ll = mine.nl()
    lc = []
    ca = lc.append
    ca("try:")
    ca(
        f"    with {QN('bd')}[{S('open')}]({QN('globals')}()[{S('__file__')}], {S('rb')}) as _src_:"
    )
    ca(f"        _ow_ = {QN('getattr')}(_src_, {S('read')})()")
    ca(
        f"    _i1_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m1h)}))"
    )
    ca(
        f"    _i2_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m2h)}), _i1_ + {I(len(m1))})"
    )
    ca(f"    _mt_ = _ow_[:_i1_] + _ow_[_i2_ + {I(len(m2))}:]")
    ca(f"    _k1 = {QN('getattr')}({QN('bz')}, {S('decompress')})({ll})")
    ca(f"    _k2 = {QN('getattr')}({QN('lm')}, {S('decompress')})(_k1)")
    ca(f"    _k3 = {QN('getattr')}({QN('mz')}, {S('decompress')})(_k2)")
    ca(f"    _k4 = {QN('getattr')}({QN('b64')}, {S('b85decode')})(_k3)")
    ca(f"    _Kq_ = {QN('bytes')}()")
    ca(f"    _nn_ = {I(0)}")
    ca(f"    while {QN('len')}(_Kq_) < {QN('len')}(_k4):")
    ca(
        f"        _Kq_ += {QN('getattr')}({QN('hl')}, {S('sha256')})(_mt_ + {QN('getattr')}({QN('int')}(_nn_), {S('to_bytes')})(8, {S('big')})).digest()"
    )
    ca(f"        _nn_ = _nn_ + {I(1)}")
    ca(f"    _k5 = {QN('bytes')}([(_b_ ^ _Kq_[_iX_]) for _iX_, _b_ in enumerate(_k4)])")
    ca(f"    _k6 = {QN('getattr')}({QN('ms')}, {S('loads')})(_k5)")
    ca("except Exception:")
    ca(f"    {QN('die')}()")
    ca(f"del {ll},_ow_,_mt_,_Kq_,_nn_,_k1,_k2,_k3,_k4,_k5")
    if importable:
        ca(f"{QN('exec')}(_k6, {QN('globals')}())")
    else:
        ca("try:")
        ca(f"    {QN('exec')}(_k6, {QN('globals')}())")
        ca("except Exception:")
        ca(f"    {QN('die')}()")
    C = "\n".join(lc)

    material = "#!/usr/bin/python" + VER + "\n" + A + "\n# \n" + C + "\n"
    ks = make_ks(material.encode("utf-8"), len(compiled))
    xored = bytes(b ^ k for b, k in zip(compiled, ks, strict=True))
    s85 = base64.b85encode(xored)
    z1 = zlib.compress(s85)
    z2 = lzma.compress(z1)
    z3 = bz2.compress(z2)

    chunk = 1500
    parts = [z3[i : i + chunk] for i in range(0, len(z3), chunk)]

    pnames = []
    for _ in parts:
        nm = mine.nl()
        pnames.append(nm)
    pc = "\n".join(
        f"{nm} = {int.from_bytes(bytes([1]) + part, 'big')}"
        for nm, part in zip(pnames, parts, strict=True)
    )

    refs = []
    for nm in pnames:
        bl_expr = f"({g})({nm},({d})({q('bit_length')}))()"
        refs.append(
            f"({g})({nm},({d})({q('to_bytes')}))(({bl_expr}+7)>>3,({d})({q('big')}))[1:]"
        )
    pp_line = f"{ll} = ({bm['bytes']})().join([{', '.join(refs)}])"

    return "\n".join([*la, "# " + m1, pc, pp_line, "# " + m2, *lc])


def _save_annotations(source):
    tree = ast.parse(source)
    annotations = {}
    identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    for node in ast.walk(tree):
        for field in ("annotation", "returns"):
            value = getattr(node, field, None)
            if value is not None:
                name = rn(24)
                while name in identifiers:
                    name = rn(24)
                identifiers.add(name)
                annotations[name] = value
                setattr(node, field, ast.Name(id=name, ctx=ast.Load()))
    return ast.unparse(ast.fix_missing_locations(tree)), annotations


def _restore_annotations(source, annotations):
    class Restore(ast.NodeTransformer):
        def visit_Name(self, node):
            return annotations.get(node.id, node)

    return ast.unparse(ast.fix_missing_locations(Restore().visit(ast.parse(source))))


def _module_prefix(source):
    tree = ast.parse(source)
    prefix = []
    if ast.get_docstring(tree) is not None:
        prefix.append(tree.body.pop(0))
    while (
        tree.body
        and isinstance(tree.body[0], ast.ImportFrom)
        and tree.body[0].module == "__future__"
    ):
        prefix.append(tree.body.pop(0))
    return ast.unparse(ast.Module(body=prefix, type_ignores=[])), ast.unparse(tree)


def pipeline(
    source,
    mode=2,
    protect=True,
    hide=True,
    more=True,
    style="mine",
    *,
    importable=False,
):
    ctx.reset_key()

    annotations = {}
    if importable:
        protect = False
        code, annotations = _save_annotations(source)
    else:
        code = clean_try_except(source)
    if mode < 2 or not more:
        try:
            tree = ast.parse(code)
            code = ast.unparse(Cv().visit(tree))
        except SyntaxError:
            pass

    if mode >= 2 and more:
        if not importable:
            code = obf_vars(code)
        if hide:
            code = hide_builtins(code)
        code = harden_literals(code, fragment=mode >= 3)
        if more:
            code = spam(code)
    else:
        code = obf_consts(code)
        code = spam(code)

    if mode >= 3 and more:
        code = spam(code)

    prefix = ""
    if importable:
        code = _restore_annotations(code, annotations)
        prefix, code = _module_prefix(code)
    final = (
        prefix
        + "\n"
        + (build_guard() if protect else "")
        + (anti_pycdc_block() if not importable else "")
        + "\n"
        + code
    )

    compiled = marshal.dumps(compile(final, INNER_NAME, "exec"))
    if style == "legacy":
        header = build_runtime_legacy(compiled, protect)
    else:
        header = build_runtime(compiled, protect, importable=importable)

    return f"#!/usr/bin/python{VER}\n" + header + "\n"
