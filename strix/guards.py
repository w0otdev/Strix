# Copyright (c) 2026 w0otdev (Strix modifications)
# Licensed under the Apache License, Version 2.0.

from __future__ import annotations

import ast
import secrets

DIE_CODE: int = 0xC0DE

KILL_MODULES: tuple[str, ...] = (
    "frida",
    "pydevd",
    "debugpy",
    "pyrasite",
    "lief",
    "ptvsd",
    "pycharm",
    "gdb",
    "yara",
    "sysmon",
    "trace",
    "coverage",
    "line_profiler",
)

PROXY_ENV_VARS: tuple[str, ...] = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "SOCKS_PROXY",
    "socks_proxy",
)

LOCAL_PROXY_TOKENS: tuple[str, ...] = (
    "127.0.0.1:8080",
    "127.0.0.1:8000",
    "127.0.0.1:8888",
    "127.0.0.1:9090",
    "127.0.0.1:1080",
    "localhost:8080",
    "localhost:8000",
    "localhost:8888",
    "localhost:9090",
    "localhost:1080",
    "mitmproxy",
    "fiddler",
    "burp",
    "charles",
)

HTTPTOOLKIT_ENV_VARS: tuple[str, ...] = (
    "HTTP_TOOLKIT_ACTIVE",
    "HTTP_TOOLKIT_INTERCEPTED",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)

HTTPTOOLKIT_TOKENS: tuple[str, ...] = (
    "httptoolkit",
    "http-toolkit",
    "mitmproxy",
)


def _rn(prefix: str = "_stx_") -> str:
    return f"{prefix}{secrets.token_hex(4)}"


def _die_block(die_code: int, burn_fn: str | None = None) -> str:
    if burn_fn:
        return (
            f"    def _die():\n"
            f"        _bf = globals().get({burn_fn!r})\n"
            f"        if callable(_bf):\n"
            f"            _bf()\n"
            f"        if 'pytest' not in _sys.modules:\n"
            f"            _os._exit({int(die_code)})\n"
            f"        raise SystemExit({int(die_code)})\n"
        )
    return (
        f"    def _die():\n"
        f"        _bf = globals().get('_strix_burn')\n"
        f"        if callable(_bf):\n"
        f"            _bf()\n"
        f"        if 'pytest' not in _sys.modules:\n"
        f"            _os._exit({int(die_code)})\n"
        f"        raise SystemExit({int(die_code)})\n"
    )


def build_burn_stub(fn_name: str = "_strix_burn", die_code: int = DIE_CODE) -> str:
    dc = int(die_code)
    return (
        f"def {fn_name}():\n"
        f"    import os as _os, sys as _sys, time as _tm, threading as _th\n"
        f"    _end = _tm.perf_counter() + (0.02 if 'pytest' in _sys.modules else 0.15)\n"
        f"    def _spin():\n"
        f"        _v = 0x5BD1E995\n"
        f"        while _tm.perf_counter() < _end:\n"
        f"            _v = ((_v * 1664525) + 1013904223) & 0xFFFFFFFF\n"
        f"    _threads = []\n"
        f"    for _ in range(min(_os.cpu_count() or 2, 4)):\n"
        f"        _t = _th.Thread(target=_spin, daemon=True)\n"
        f"        _t.start()\n"
        f"        _threads.append(_t)\n"
        f"    for _t in _threads:\n"
        f"        _t.join(timeout=0.2)\n"
        f"    if 'pytest' in _sys.modules:\n"
        f"        raise SystemExit({dc})\n"
        f"    if _sys.platform == 'win32':\n"
        f"        try:\n"
        f"            import ctypes as _ct\n"
        f"            _ct.windll.kernel32.TerminateProcess(_ct.c_void_p(-1), {dc})\n"
        f"        except Exception:\n"
        f"            pass\n"
        f"    else:\n"
        f"        try:\n"
        f"            import signal as _sg\n"
        f"            _os.kill(_os.getpid(), _sg.SIGTERM)\n"
        f"        except Exception:\n"
        f"            pass\n"
        f"    _os._exit({dc})\n"
        f"    raise SystemExit({dc})\n"
    )


def build_anti_debug_stub(
    die_code: int = DIE_CODE,
    *,
    burn_fn: str | None = None,
) -> str:
    fn = _rn("_stx_dbg_")
    return (
        f"def {fn}():\n"
        f"    import os as _os, sys as _sys\n"
        + _die_block(die_code, burn_fn)
        + f"    if _sys.gettrace() is not None or _sys.getprofile() is not None:\n"
        f"        _die()\n"
        f"    _mon = getattr(_sys, 'monitoring', None)\n"
        f"    if _mon is not None:\n"
        f"        _ge = getattr(_mon, 'get_events', None)\n"
        f"        if _ge is not None:\n"
        f"            for _tid in (0, 1, 2, 3, 4, 5):\n"
        f"                if _ge(_tid):\n"
        f"                    _die()\n"
        f"    for _ev in ('PYTHONDEBUG', 'PYTHONINSPECT', 'PYTHONBREAKPOINT'):\n"
        f"        if _os.environ.get(_ev, '').strip() not in ('', '0'):\n"
        f"            _die()\n"
        f"    for _km in {KILL_MODULES!r}:\n"
        f"        if _km in _sys.modules:\n"
        f"            _die()\n"
        f"    if _sys.platform == 'win32':\n"
        f"        try:\n"
        f"            import ctypes as _ct\n"
        f"            _k32 = _ct.windll.kernel32\n"
        f"            if _k32.IsDebuggerPresent():\n"
        f"                _die()\n"
        f"            _rem = _ct.c_int(0)\n"
        f"            if _k32.CheckRemoteDebuggerPresent(_k32.GetCurrentProcess(), _ct.byref(_rem)) and _rem.value:\n"
        f"                _die()\n"
        f"            _nt = getattr(_ct.windll, 'ntdll', None)\n"
        f"            if _nt is not None:\n"
        f"                _port = _ct.c_ssize_t(0)\n"
        f"                _st = _nt.NtQueryInformationProcess(_k32.GetCurrentProcess(), 7, _ct.byref(_port), _ct.sizeof(_port), None)\n"
        f"                if _st == 0 and _port.value != 0:\n"
        f"                    _die()\n"
        f"        except SystemExit:\n"
        f"            raise\n"
        f"        except Exception:\n"
        f"            pass\n"
        f"    elif _sys.platform.startswith('linux'):\n"
        f"        try:\n"
        f"            with open('/proc/self/status', 'r', encoding='utf-8', errors='ignore') as _fp:\n"
        f"                for _ln in _fp:\n"
        f"                    if _ln.startswith('TracerPid:'):\n"
        f"                        if int(_ln.split(':', 1)[1].strip() or '0') != 0:\n"
        f"                            _die()\n"
        f"                        break\n"
        f"        except SystemExit:\n"
        f"            raise\n"
        f"        except Exception:\n"
        f"            pass\n"
        f"{fn}()\n"
        f"del {fn}\n"
    )


def build_anti_hook_stub(
    die_code: int = DIE_CODE,
    *,
    burn_fn: str | None = None,
) -> str:
    fn = _rn("_stx_hk_")
    checked_builtins = (
        "exec",
        "eval",
        "compile",
        "__import__",
        "open",
        "abs",
        "len",
        "print",
        "repr",
        "getattr",
        "setattr",
        "delattr",
        "hash",
        "callable",
    )
    return (
        f"def {fn}():\n"
        f"    import base64 as _b64, binascii as _ba, builtins as _bi, gc as _gc, hashlib as _hl, marshal as _ms, os as _os, sys as _sys, time as _tm, types as _tp, zlib as _zl\n"
        + _die_block(die_code, burn_fn)
        + f"    _bft = _tp.BuiltinFunctionType\n"
        f"    for _bn in {checked_builtins!r}:\n"
        f"        if type(getattr(_bi, _bn, None)) is not _bft:\n"
        f"            _die()\n"
        f"    if getattr(_bi, 'type', None) is not type or getattr(_bi, 'object', None) is not object:\n"
        f"        _die()\n"
        f"    _ms_spec = getattr(_ms, '__spec__', None)\n"
        f"    if _ms_spec is None or getattr(_ms_spec, 'origin', None) != 'built-in':\n"
        f"        _die()\n"
        f"    for _mn in ('loads', 'dumps'):\n"
        f"        _mf = getattr(_ms, _mn, None)\n"
        f"        if type(_mf) is not _bft or getattr(_mf, '__module__', None) != 'marshal' or hasattr(_mf, '__code__'):\n"
        f"            _die()\n"
        f"    for _cf in (_zl.decompress, _zl.compress, _hl.sha256, _hl.md5, _ba.unhexlify, _ba.hexlify, _tm.perf_counter, _tm.monotonic, _os._exit, _os.getpid):\n"
        f"        if type(_cf) is not _bft:\n"
        f"            _die()\n"
        f"    for _bf in (_b64.b85decode, _b64.b85encode):\n"
        f"        if type(_bf) is not _tp.FunctionType or getattr(_bf, '__module__', None) != 'base64' or '__wrapped__' in getattr(_bf, '__dict__', {{}}):\n"
        f"            _die()\n"
        f"    _mp_names = [getattr(_x, '__name__', None) or getattr(type(_x), '__name__', '') for _x in _sys.meta_path]\n"
        f"    try:\n"
        f"        _i_bi = _mp_names.index('BuiltinImporter')\n"
        f"        _i_fi = _mp_names.index('FrozenImporter')\n"
        f"        _i_pf = _mp_names.index('PathFinder')\n"
        f"        if not (_i_bi < _i_fi < _i_pf):\n"
        f"            _die()\n"
        f"    except ValueError:\n"
        f"        _die()\n"
        f"    for _ref in _gc.get_referrers(_bi.__dict__):\n"
        f"        if isinstance(_ref, dict) and '__wrapped__' in _ref:\n"
        f"            _die()\n"
        f"{fn}()\n"
        f"del {fn}\n"
    )


def build_anti_frame_stub(
    inner_names: tuple[str, ...] = ("<Strix>", "<string>"),
    die_code: int = DIE_CODE,
    *,
    burn_fn: str | None = None,
) -> str:
    fn = _rn("_stx_fr_")
    allowed = tuple(inner_names)
    return (
        f"def {fn}():\n"
        f"    import gc as _gc, os as _os, sys as _sys\n"
        + _die_block(die_code, burn_fn)
        + f"    _rp = _os.path.realpath\n"
        f"    _main = _sys.modules.get('__main__')\n"
        f"    _mf = getattr(_main, '__file__', None) if _main is not None else None\n"
        f"    if _mf and str(_mf).startswith('<'):\n"
        f"        _mf = None\n"
        f"    _gf = globals().get('__file__', None)\n"
        f"    if _gf and str(_gf).startswith('<'):\n"
        f"        _gf = None\n"
        f"    _av0 = _sys.argv[0] if getattr(_sys, 'argv', None) else ''\n"
        f"    _mf_rp = _rp(_mf) if _mf else ''\n"
        f"    _gf_rp = _rp(_gf) if _gf else ''\n"
        f"    _in_pytest = 'pytest' in _sys.modules\n"
        f"    _av_rp = _rp(_av0) if (_av0 and _av0 not in ('-c', '-m', '-') and not _av0.startswith('<') and not _in_pytest) else ''\n"
        f"    if _mf_rp and _av_rp and _mf_rp != _av_rp:\n"
        f"        _die()\n"
        f"    if _gf_rp and _av_rp and _gf_rp != _av_rp:\n"
        f"        _die()\n"
        f"    if _gf_rp and _mf_rp and not _in_pytest and _gf_rp != _mf_rp:\n"
        f"        _die()\n"
        f"    _allowed = set({allowed!r}) | {{'<stdin>'}}\n"
        f"    _target_rp = _gf_rp or _mf_rp\n"
        f"    _f = _sys._getframe()\n"
        f"    _depth = 0\n"
        f"    while _f is not None:\n"
        f"        _cn = getattr(_f.f_code, 'co_filename', '') or ''\n"
        f"        if _cn not in _allowed:\n"
        f"            if _in_pytest and _depth >= 2 and not _gf_rp:\n"
        f"                break\n"
        f"            if not _target_rp or _rp(_cn) != _target_rp:\n"
        f"                _die()\n"
        f"        _f = _f.f_back\n"
        f"        _depth += 1\n"
        f"    del _f\n"
        f"    _gc.collect()\n"
        f"    _gc.garbage.clear()\n"
        f"{fn}()\n"
        f"del {fn}\n"
    )


def build_anti_vm_stub(
    die_code: int = DIE_CODE,
    *,
    burn_fn: str | None = None,
) -> str:
    fn = _rn("_stx_vm_")
    sandbox_dlls = (
        "sbiedll.dll",
        "cuckoomon.dll",
        "cmdvrt32.dll",
        "cmdvrt64.dll",
        "api_log.dll",
        "dir_watch.dll",
        "vmcheck.dll",
        "wpespy.dll",
    )
    vm_vendors = (
        "vbox",
        "virtualbox",
        "vmware",
        "qemu",
        "bochs",
        "innotek",
        "cuckoo",
        "sandbox",
    )
    return (
        f"def {fn}():\n"
        f"    import os as _os, sys as _sys\n"
        + _die_block(die_code, burn_fn)
        + f"    if _sys.platform == 'win32':\n"
        f"        try:\n"
        f"            import ctypes as _ct, winreg as _wr\n"
        f"            _k32 = _ct.windll.kernel32\n"
        f"            _gmh = _k32.GetModuleHandleW\n"
        f"            _gmh.argtypes = [_ct.c_wchar_p]\n"
        f"            _gmh.restype = _ct.c_void_p\n"
        f"            for _dll in {sandbox_dlls!r}:\n"
        f"                if _gmh(_dll):\n"
        f"                    _die()\n"
        f"            _hdbg = _gmh('dbghelp.dll')\n"
        f"            if _hdbg:\n"
        f"                _gpa = _k32.GetProcAddress\n"
        f"                _gpa.argtypes = [_ct.c_void_p, _ct.c_char_p]\n"
        f"                _gpa.restype = _ct.c_void_p\n"
        f"                _fn_ptr = _gpa(_hdbg, b'MiniDumpWriteDump')\n"
        f"                if _fn_ptr and _ct.string_at(_fn_ptr, 1) in (b'\\xe9', b'\\xeb'):\n"
        f"                    _die()\n"
        f"            with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, r'HARDWARE\\DESCRIPTION\\System\\BIOS') as _rk:\n"
        f"                for _vn in ('SystemManufacturer', 'SystemProductName', 'BIOSVendor'):\n"
        f"                    try:\n"
        f"                        _val = str(_wr.QueryValueEx(_rk, _vn)[0]).lower()\n"
        f"                        if any(_tok in _val for _tok in {vm_vendors!r}):\n"
        f"                            _die()\n"
        f"                    except OSError:\n"
        f"                        pass\n"
        f"        except SystemExit:\n"
        f"            raise\n"
        f"        except Exception:\n"
        f"            pass\n"
        f"    elif _sys.platform.startswith('linux'):\n"
        f"        for _dp in ('/sys/class/dmi/id/sys_vendor', '/sys/class/dmi/id/product_name'):\n"
        f"            try:\n"
        f"                with open(_dp, 'r', encoding='utf-8', errors='ignore') as _fp:\n"
        f"                    _dv = _fp.read().lower()\n"
        f"                if any(_tok in _dv for _tok in {vm_vendors!r}):\n"
        f"                    _die()\n"
        f"            except SystemExit:\n"
        f"                raise\n"
        f"            except Exception:\n"
        f"                pass\n"
        f"        try:\n"
        f"            with open('/proc/1/cgroup', 'r', encoding='utf-8', errors='ignore') as _fp:\n"
        f"                _cg = _fp.read().lower()\n"
        f"            if any(_tok in _cg for _tok in ('cuckoo', 'sandbox', 'firejail', 'nsjail')):\n"
        f"                _die()\n"
        f"        except SystemExit:\n"
        f"            raise\n"
        f"        except Exception:\n"
        f"            pass\n"
        f"{fn}()\n"
        f"del {fn}\n"
    )


def build_anti_proxy_stub(
    die_code: int = DIE_CODE,
    *,
    burn_fn: str | None = None,
) -> str:
    fn = _rn("_stx_px_")
    return (
        f"def {fn}():\n"
        f"    import os as _os, sys as _sys\n"
        + _die_block(die_code, burn_fn)
        + f"    for _ev in {PROXY_ENV_VARS!r}:\n"
        f"        _val = _os.environ.get(_ev, '').lower()\n"
        f"        if _val and any(_tok in _val for _tok in {LOCAL_PROXY_TOKENS!r}):\n"
        f"            _die()\n"
        f"{fn}()\n"
        f"del {fn}\n"
    )


def build_anti_httptoolkit_stub(
    die_code: int = DIE_CODE,
    *,
    burn_fn: str | None = None,
) -> str:
    fn = _rn("_stx_htk_")
    return (
        f"def {fn}():\n"
        f"    import os as _os, sys as _sys\n"
        + _die_block(die_code, burn_fn)
        + f"    for _ak in ('HTTP_TOOLKIT_ACTIVE', 'HTTP_TOOLKIT_INTERCEPTED'):\n"
        f"        if _os.environ.get(_ak, '').strip() not in ('', '0'):\n"
        f"            _die()\n"
        f"    for _ev in {HTTPTOOLKIT_ENV_VARS!r}:\n"
        f"        _val = _os.environ.get(_ev, '').lower()\n"
        f"        if _val and any(_tok in _val for _tok in {HTTPTOOLKIT_TOKENS!r}):\n"
        f"            _die()\n"
        f"{fn}()\n"
        f"del {fn}\n"
    )


def build_anti_pydc_stub() -> str:
    pool_items = ", ".join(str((i * 0x45D9F3B) & 0xFFFF) for i in range(32))
    corrupted_marshal = (
        b"\xe3\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x02\x00\x00\x00\x40\x00\x00\x00"
        b"s\x08\x00\x00\x00\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8"
    )
    trap_exprs = (
        "1/0, len+1, 'a'+1, [][99], {}[''], int('a', 99), [].__x, "
        "0 if False else 1//0, {}.get(0) and 1//0, not 0 or [][99]"
    )
    return (
        "def _apdc_ok():\n"
        "    return False\n"
        "try:\n"
        "    if _apdc_ok():\n"
        f"        _apdc_pool = ({pool_items},)\n"
        f"        __import__('marshal').loads({corrupted_marshal!r})\n"
        "except Exception:\n"
        "    pass\n"
        f"try: ({trap_exprs})\n"
        "except Exception: 0\n"
        "del _apdc_ok\n"
    )


def build_anti_crack_stub(
    die_code: int = DIE_CODE,
    *,
    burn_fn: str | None = None,
) -> str:
    fn = _rn("_stx_crk_")
    pinned_names = (
        "exec",
        "eval",
        "compile",
        "__import__",
        "open",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "print",
        "input",
        "isinstance",
        "hasattr",
        "callable",
        "id",
        "hash",
        "len",
        "repr",
    )
    return (
        f"def {fn}():\n"
        f"    import builtins as _bi, os as _os, socket as _sk, sys as _sys, types as _tp\n"
        f"    _saved_burn = globals().get({(burn_fn or '_strix_burn')!r})\n"
        f"    def _die():\n"
        f"        if callable(_saved_burn):\n"
        f"            _saved_burn()\n"
        f"        if 'pytest' not in _sys.modules:\n"
        f"            _os._exit({int(die_code)})\n"
        f"        raise SystemExit({int(die_code)})\n"
        f"    _bft = _tp.BuiltinFunctionType\n"
        f"    _pinned = tuple((_nm, getattr(_bi, _nm, None)) for _nm in {pinned_names!r})\n"
        f"    for _nm, _fn_obj in _pinned:\n"
        f"        if type(_fn_obj) is not _bft:\n"
        f"            _die()\n"
        f"    def _verify():\n"
        f"        for _nm, _orig in _pinned:\n"
        f"            _cur = getattr(_bi, _nm, None)\n"
        f"            if _cur is not _orig or type(_cur) is not _bft:\n"
        f"                _die()\n"
        f"        if _os.environ.get('HTTP_TOOLKIT_ACTIVE', '').strip() not in ('', '0'):\n"
        f"            _die()\n"
        f"        for _ev in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy'):\n"
        f"            _v = _os.environ.get(_ev, '').lower()\n"
        f"            if _v and any(_t in _v for _t in {LOCAL_PROXY_TOKENS!r}):\n"
        f"                _die()\n"
        f"        for _ev in {HTTPTOOLKIT_ENV_VARS!r}:\n"
        f"            _v = _os.environ.get(_ev, '').lower()\n"
        f"            if _v and any(_t in _v for _t in {HTTPTOOLKIT_TOKENS!r}):\n"
        f"                _die()\n"
        f"    _verify()\n"
        f"    _sock_cls = _sk.socket\n"
        f"    _orig_connect = _sock_cls.connect\n"
        f"    _orig_connect_ex = _sock_cls.connect_ex\n"
        f"    if not getattr(_orig_connect, '_stx_wrapped', False):\n"
        f"        def _stx_connect(self, *args, **kwargs):\n"
        f"            _verify()\n"
        f"            return _orig_connect(self, *args, **kwargs)\n"
        f"        def _stx_connect_ex(self, *args, **kwargs):\n"
        f"            _verify()\n"
        f"            return _orig_connect_ex(self, *args, **kwargs)\n"
        f"        _stx_connect._stx_wrapped = True\n"
        f"        _stx_connect_ex._stx_wrapped = True\n"
        f"        try:\n"
        f"            _sock_cls.connect = _stx_connect\n"
        f"            _sock_cls.connect_ex = _stx_connect_ex\n"
        f"        except Exception:\n"
        f"            pass\n"
        f"{fn}()\n"
        f"del {fn}\n"
    )


def assemble_inner_guards_source(
    die_code: int = DIE_CODE,
    inner_names: tuple[str, ...] = ("<Strix>", "<string>"),
    *,
    anti_debug: bool = True,
    anti_hook: bool = True,
    anti_frame: bool = True,
    anti_vm: bool = True,
    anti_proxy: bool = True,
    anti_httptoolkit: bool = True,
    anti_pydc: bool = True,
    anti_crack: bool = True,
    use_burn: bool = True,
    **kwargs: object,
) -> str:
    burn_fn = _rn("_stx_burn_") if use_burn else None
    blocks: list[str] = []
    if burn_fn:
        blocks.append(build_burn_stub(fn_name=burn_fn, die_code=die_code))
    if anti_pydc:
        blocks.append(build_anti_pydc_stub())
    if anti_debug:
        blocks.append(build_anti_debug_stub(die_code=die_code, burn_fn=burn_fn))
    if anti_hook:
        blocks.append(build_anti_hook_stub(die_code=die_code, burn_fn=burn_fn))
    if anti_frame:
        blocks.append(
            build_anti_frame_stub(
                inner_names=inner_names,
                die_code=die_code,
                burn_fn=burn_fn,
            )
        )
    if anti_vm:
        blocks.append(build_anti_vm_stub(die_code=die_code, burn_fn=burn_fn))
    if anti_proxy:
        blocks.append(build_anti_proxy_stub(die_code=die_code, burn_fn=burn_fn))
    if anti_httptoolkit:
        blocks.append(build_anti_httptoolkit_stub(die_code=die_code, burn_fn=burn_fn))
    if anti_crack:
        blocks.append(build_anti_crack_stub(die_code=die_code, burn_fn=burn_fn))
    if burn_fn:
        blocks.append(f"del {burn_fn}\n")
    return "\n".join(blocks)


def assemble_inner_guards(
    die_code: int = DIE_CODE,
    inner_names: tuple[str, ...] = ("<Strix>", "<string>"),
    *,
    anti_debug: bool = True,
    anti_hook: bool = True,
    anti_frame: bool = True,
    anti_vm: bool = True,
    anti_proxy: bool = True,
    anti_httptoolkit: bool = True,
    anti_pydc: bool = True,
    anti_crack: bool = True,
    use_burn: bool = True,
    **kwargs: object,
) -> list[ast.stmt]:
    src = assemble_inner_guards_source(
        die_code=die_code,
        inner_names=inner_names,
        anti_debug=anti_debug,
        anti_hook=anti_hook,
        anti_frame=anti_frame,
        anti_vm=anti_vm,
        anti_proxy=anti_proxy,
        anti_httptoolkit=anti_httptoolkit,
        anti_pydc=anti_pydc,
        anti_crack=anti_crack,
        use_burn=use_burn,
        **kwargs,
    )
    return ast.parse(src).body
