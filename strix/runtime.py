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

    ln = rn()
    L = []
    a = L.append

    a(f"for _n_ in ({', '.join(S(x) for x in KILL_MODULES)}):")
    a(f"    if _n_ in {ga}({sm}, {S('modules')}): {die}()")
    a(f"for _en_ in ({S('PYTHONBREAKPOINT')}, {S('PYTHONPYCACHEPREFIX')}):")
    a(f"    if {S('breakpoint')} in {osm}.environ.get(_en_, {S('')}).lower(): {die}()")
    a("try:")
    a(f"    _m_ = {ga}({sm}, {S('monitoring')})")
    a(f"    _ge_ = {ga}(_m_, {S('get_events')})")
    a("    for _tid_ in (0, 1, 2, 3, 4, 5):")
    a(f"        if _ge_(_tid_): {die}()")
    a("except Exception:")
    a("    pass")
    a("try:")
    a(
        f"    if {T('type')}({ga}({ms}, {S('loads')})) != {T('type')}({T('len')}): {die}()"
    )
    a(
        f"    if {ga}({ga}({ms}, {S('loads')}), {S('__name__')}, {S('')}) != {S('loads')}: {die}()"
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
    a(f"if {T('type')}({T('exec')}) != {T('type')}({T('len')}): {die}()")
    a(f"if {T('type')}({T('compile')}) != {T('type')}({T('len')}): {die}()")
    a(f"if {T('type')}({T('__import__')}) != {T('type')}({T('len')}): {die}()")
    a(
        f"if {T('type')}({ga}({sm}, {S('gettrace')})) != {T('type')}({T('len')}): {die}()"
    )
    a(
        f"if {T('type')}({ga}({sm}, {S('setprofile')})) != {T('type')}({T('len')}): {die}()"
    )
    a(f"def {ln}():")
    a(f"    _rp_ = {ga}({ga}({osm}, {S('path')}), {S('realpath')})")
    a(f"    _me_ = {ga}(({QN('globals')})(), {S('get')})({S('__file__')}, {S('')})")
    a(f"    _me_ = _rp_(_me_) if _me_ else {S('')}")
    a(f"    _af_ = {ga}({sm}, {S('argv')})[0] if {ga}({sm}, {S('argv')}) else {S('')}")
    a(f"    _af_ = _rp_(_af_) if _af_ else {S('')}")
    a(f"    if not _me_ or _me_ != _af_: {die}()")
    a(f"    _f_ = {ga}({sm}, {S('_getframe')})()")
    a("    while _f_ is not None:")
    a(f"        _c_ = {ga}({ga}(_f_, {S('f_code')}), {S('co_filename')}) or {S('')}")
    a(
        f"        if _c_ != {S(INNER_NAME)} and (_rp_(_c_) if _c_ else {S('')}) != _me_: {die}()"
    )
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
            f"    _ge_ = {QN('getattr')}({QN('getattr')}({QN('sysm')},{S('monitoring')}),{S('get_events')})\n"
            f"    for _tid_ in (0, 1, 2, 3, 4, 5):\n"
            f"        if _ge_(_tid_):\n"
            f"            {QN('die')}()\n"
            f"except Exception:\n"
            f"    pass\n"
        )
    )


def _build_loader_and_parts(la, ll, m1, m2, compiled):
    m1h = m1.encode().hex()
    m2h = m2.encode().hex()
    lc = [
        "try:",
        f"    with {QN('bd')}[{S('open')}]({QN('globals')}()[{S('__file__')}], {S('rb')}) as _src_:",
        f"        _ow_ = {QN('getattr')}({QN('getattr')}(_src_, {S('read')})(), {S('replace')})(b'\\r\\n', b'\\n')",
        f"    _i1_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m1h)}))",
        f"    _i2_ = {QN('getattr')}(_ow_, {S('index')})({QN('getattr')}({QN('bytes')}, {S('fromhex')})({S(m2h)}), _i1_ + {I(len(m1))})",
        f"    _mt_ = _ow_[:_i1_] + _ow_[_i2_ + {I(len(m2))}:]",
        f"    _k1 = {QN('getattr')}({QN('b64')}, {S('b85decode')})({ll})",
        f"    _hb_ = {QN('getattr')}({QN('hl')}, {S('sha256')})(_mt_)",
        "    _Kl_ = []",
        f"    for _nn_ in range(({QN('len')}(_k1) + 31) // 32):",
        "        _hc_ = _hb_.copy()",
        f"        _hc_.update({QN('getattr')}({QN('int')}(_nn_), {S('to_bytes')})(8, {S('big')}))",
        "        _Kl_.append(_hc_.digest())",
        "    _Kq_ = b''.join(_Kl_)",
        f"    _k2 = {QN('bytes')}([(_b_ ^ _Kq_[_iX_]) for _iX_, _b_ in enumerate(_k1)])",
        f"    _k3 = {QN('getattr')}({QN('bz')}, {S('decompress')})(_k2)",
        f"    _k4 = {QN('getattr')}({QN('lm')}, {S('decompress')})(_k3)",
        f"    _k5 = {QN('getattr')}({QN('mz')}, {S('decompress')})(_k4)",
        f"    _k6 = {QN('getattr')}({QN('ms')}, {S('loads')})(_k5)",
        "except Exception:",
        f"    {QN('die')}()",
        f"del {ll},_ow_,_mt_,_hb_,_Kl_,_Kq_,_k1,_k2,_k3,_k4,_k5",
        f"{QN('exec')}({QN('globals')}().pop({S('_k6')}), {QN('globals')}())",
    ]
    material = (
        "#!/usr/bin/python" + VER + "\n" + "\n".join(la) + "\n# \n" + "\n".join(lc) + "\n"
    )
    z3 = bz2.compress(lzma.compress(zlib.compress(compiled)))
    ks = make_ks(material.encode("utf-8"), len(z3))
    s85 = base64.b85encode(bytes(a ^ b for a, b in zip(z3, ks, strict=True)))
    parts = [s85[i : i + 1500] for i in range(0, len(s85), 1500)]
    return lc, parts


def build_runtime_legacy(compiled, protect=True):
    m1 = mkmarker()
    m2 = mkmarker()

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
        f"{QN('dec')} = (lambda {QN('join')},{QN('chr')},_k_,_o_: (lambda _s_: {QN('join')}({QN('chr')}((_x_ - _o_) ^ ((_k_ + _i_ * 0x5BD1E995) & 0xFFFFFFFF)) for _i_, _x_ in enumerate(_s_))))({QN('join')},{QN('chr')},{ctx.K},{OFF})"
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

    lc, parts = _build_loader_and_parts(la, "_pp_", m1, m2, compiled)
    pnames = [rn() for _ in parts]
    refs = [
        f"{QN('getattr')}({pname} , {S('to_bytes')})(({QN('getattr')}({pname} , {S('bit_length')})() + 7) // 8, {S('big')})[1:]"
        for pname in pnames
    ]
    pc = "\n".join(
        f"{pname} = {int.from_bytes(bytes([1]) + part, 'big')}"
        for pname, part in zip(pnames, parts, strict=True)
    )
    pp = f"_pp_ = {QN('getattr')}({QN('bytes')}(), {S('join')})([{', '.join(refs)}])"
    return "\n".join([*la, "# " + m1, pc, pp, "# " + m2, *lc])


def build_runtime(compiled, protect=True, *, importable=False):
    m1 = mkmarker()
    m2 = mkmarker()

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
        '"".join(chr((_m_ - '
        + str(OFF)
        + ") ^ (("
        + str(ctx.K)
        + " + _i_ * 0x5BD1E995) & 0xFFFFFFFF)) for _i_, _m_ in enumerate("
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
        f"({deca}) = (lambda _j_,_c_,_k_,_o_:(lambda _s_:_j_(_c_((_x_-_o_)^((_k_+_i_*0x5BD1E995)&0xFFFFFFFF)) for _i_,_x_ in enumerate(_s_))))(({bm['str']})().join,({bm['chr']}),{ctx.K},{OFF})"
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

    ll = mine.nl()
    lc, parts = _build_loader_and_parts(la, ll, m1, m2, compiled)
    pnames = [mine.nl() for _ in parts]
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


def _module_prefix(source, annotations=None):
    tree = ast.parse(source)
    if annotations:

        class Restore(ast.NodeTransformer):
            def visit_Name(self, node):
                return annotations.get(node.id, node)

        tree = ast.fix_missing_locations(Restore().visit(tree))
    prefix = []
    if ast.get_docstring(tree) is not None:
        prefix.append(tree.body.pop(0))
    while (
        tree.body
        and isinstance(tree.body[0], ast.ImportFrom)
        and tree.body[0].module == "__future__"
    ):
        prefix.append(tree.body.pop(0))
    if not prefix and not annotations:
        return "", source
    return (
        ast.unparse(ast.Module(body=prefix, type_ignores=[])) if prefix else "",
        ast.unparse(tree),
    )


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
        code = spam(code)
    else:
        code = obf_consts(code)
        code = spam(code)

    prefix, code = _module_prefix(code, annotations)
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
