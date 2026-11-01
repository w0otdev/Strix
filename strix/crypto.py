# Copyright (c) 2026 w0otdev (Strix modifications)
# Licensed under the Apache License, Version 2.0.

"""High-speed 5-layer payload encryption, HKDF-SHA256, and hardware binding."""

import hashlib
import hmac
import os
import platform
import random
import secrets
import struct
import sys
import uuid
import zlib

_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F)
_XTIME = tuple(((i << 1) ^ 0x1B) & 0xFF if i & 0x80 else (i << 1) & 0xFF for i in range(256))


def _aes_key_expansion(key: bytes) -> list[list[int]]:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    w = list(key)
    sbox = _AES_SBOX
    rcon = _AES_RCON
    for i in range(8, 60):
        t0, t1, t2, t3 = w[(i - 1) * 4 : i * 4]
        if i % 8 == 0:
            t0, t1, t2, t3 = sbox[t1] ^ rcon[i // 8 - 1], sbox[t2], sbox[t3], sbox[t0]
        elif i % 8 == 4:
            t0, t1, t2, t3 = sbox[t0], sbox[t1], sbox[t2], sbox[t3]
        base = (i - 8) * 4
        w.extend((w[base] ^ t0, w[base + 1] ^ t1, w[base + 2] ^ t2, w[base + 3] ^ t3))
    return [w[16 * r : 16 * (r + 1)] for r in range(15)]


def _aes_encrypt_block(block: bytes, rks: list[list[int]]) -> bytes:
    s = list(block)
    sbox = _AES_SBOX
    xt = _XTIME
    rk0 = rks[0]
    for i in range(16):
        s[i] ^= rk0[i]
    for rnd in range(1, 14):
        s = [sbox[b] for b in s]
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        rk = rks[rnd]
        for c in (0, 4, 8, 12):
            a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
            x0, x1, x2, x3 = xt[a0], xt[a1], xt[a2], xt[a3]
            s[c] = x0 ^ x1 ^ a1 ^ a2 ^ a3 ^ rk[c]
            s[c + 1] = a0 ^ x1 ^ x2 ^ a2 ^ a3 ^ rk[c + 1]
            s[c + 2] = a0 ^ a1 ^ x2 ^ x3 ^ a3 ^ rk[c + 2]
            s[c + 3] = x0 ^ a0 ^ a1 ^ a2 ^ x3 ^ rk[c + 3]
    s = [sbox[b] for b in s]
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    rk14 = rks[14]
    for i in range(16):
        s[i] ^= rk14[i]
    return bytes(s)


def _ghash(h_bytes: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h_int = int.from_bytes(h_bytes, "big")

    def _gf128_mul(x: int, v: int) -> int:
        z = 0
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ (0xE1 << 120)
            else:
                v >>= 1
        return z

    def _pad16(d: bytes) -> bytes:
        r = len(d) & 15
        return d + b"\x00" * (16 - r) if r else d

    data = _pad16(aad) + _pad16(ciphertext) + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    y = 0
    for i in range(0, len(data), 16):
        y = _gf128_mul(y ^ int.from_bytes(data[i : i + 16], "big"), h_int)
    return y.to_bytes(16, "big")


def aes256_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", iv: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    rks = _aes_key_expansion(key)
    if iv is None:
        iv = os.urandom(12)
    h_bytes = _aes_encrypt_block(b"\x00" * 16, rks)
    j0_enc = _aes_encrypt_block(iv + b"\x00\x00\x00\x01", rks)
    ct = bytearray()
    for i in range(0, len(plaintext), 16):
        ks = _aes_encrypt_block(iv + struct.pack(">I", i // 16 + 2), rks)
        chunk = plaintext[i : i + 16]
        ct.extend(b ^ k for b, k in zip(chunk, ks))
    ct_bytes = bytes(ct)
    tag = _ghash(h_bytes, aad, ct_bytes)
    tag = bytes(a ^ b for a, b in zip(tag, j0_enc))
    return iv, ct_bytes, tag


def aes256_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    rks = _aes_key_expansion(key)
    h_bytes = _aes_encrypt_block(b"\x00" * 16, rks)
    j0_enc = _aes_encrypt_block(iv + b"\x00\x00\x00\x01", rks)
    expected_tag = _ghash(h_bytes, aad, ciphertext)
    expected_tag = bytes(a ^ b for a, b in zip(expected_tag, j0_enc))
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("AES-GCM authentication tag mismatch")
    pt = bytearray()
    for i in range(0, len(ciphertext), 16):
        ks = _aes_encrypt_block(iv + struct.pack(">I", i // 16 + 2), rks)
        chunk = ciphertext[i : i + 16]
        pt.extend(b ^ k for b, k in zip(chunk, ks))
    return bytes(pt)


def _chacha20_quarter(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = ((d << 16) | (d >> 16)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = ((b << 12) | (b >> 20)) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = ((d << 8) | (d >> 24)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = ((b << 7) | (b >> 25)) & 0xFFFFFFFF
    return a, b, c, d


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    st = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        w[0], w[4], w[8], w[12] = _chacha20_quarter(w[0], w[4], w[8], w[12])
        w[1], w[5], w[9], w[13] = _chacha20_quarter(w[1], w[5], w[9], w[13])
        w[2], w[6], w[10], w[14] = _chacha20_quarter(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15] = _chacha20_quarter(w[3], w[7], w[11], w[15])
        w[0], w[5], w[10], w[15] = _chacha20_quarter(w[0], w[5], w[10], w[15])
        w[1], w[6], w[11], w[12] = _chacha20_quarter(w[1], w[6], w[11], w[12])
        w[2], w[7], w[8], w[13] = _chacha20_quarter(w[2], w[7], w[8], w[13])
        w[3], w[4], w[9], w[14] = _chacha20_quarter(w[3], w[4], w[9], w[14])
    return struct.pack("<16I", *((w[i] + st[i]) & 0xFFFFFFFF for i in range(16)))


def chacha20_encrypt(data: bytes, key: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    if nonce is None:
        nonce = os.urandom(12)
    out = bytearray()
    for i, off in enumerate(range(0, len(data), 64)):
        ks = _chacha20_block(key, i, nonce)
        chunk = data[off : off + 64]
        out.extend(b ^ k for b, k in zip(chunk, ks))
    return nonce, bytes(out)


def chacha20_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    return chacha20_encrypt(data, key, nonce)[1]


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t = b""
    okm = bytearray()
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)
        i += 1
    return bytes(okm[:length])


def hkdf(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def xorshift_stream(data: bytes, key_b: bytes) -> bytes:
    x = int.from_bytes(key_b[:8], "big") or 0xDEADBEEFCAFEBABE
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        out[i] = byte ^ (x & 0xFF)
    return bytes(out)


xorshift_unstream = xorshift_stream


def _seed_from_key(key_c: bytes, perm_tag: bytes = b"strix_perm") -> int:
    return int.from_bytes(hashlib.sha256(key_c + perm_tag).digest()[:8], "big")


def byte_shuffle(data: bytes, key_c: bytes, perm_tag: bytes = b"strix_perm") -> bytes:
    n = len(data)
    if not n:
        return data
    rng = random.Random(_seed_from_key(key_c, perm_tag))
    indices = list(range(n))
    rng.shuffle(indices)
    out = bytearray(n)
    for new_pos, old_pos in enumerate(indices):
        out[new_pos] = data[old_pos]
    return bytes(out)


def byte_unshuffle(data: bytes, key_c: bytes, perm_tag: bytes = b"strix_perm") -> bytes:
    n = len(data)
    if not n:
        return data
    rng = random.Random(_seed_from_key(key_c, perm_tag))
    indices = list(range(n))
    rng.shuffle(indices)
    out = bytearray(n)
    for new_pos, old_pos in enumerate(indices):
        out[old_pos] = data[new_pos]
    return bytes(out)


def get_inline_hw_fp_src(fn_name: str = "_strix_hwfp") -> str:
    return (
        f"def {fn_name}():\n"
        " import uuid as _u,platform as _p,hashlib as _h\n"
        " _v=[]\n"
        " for _f in (lambda:str(_u.getnode()),_p.node,_p.machine,_p.system):\n"
        "  try:_v.append(str(_f()))\n"
        "  except Exception:pass\n"
        " _s=_p.system()\n"
        " if _s=='Windows':\n"
        "  try:\n"
        "   import ctypes as _ct\n"
        "   _b=_ct.create_unicode_buffer(256);_sr=_ct.c_ulong(0)\n"
        "   if _ct.windll.kernel32.GetVolumeInformationW(_ct.c_wchar_p('C:\\\\'),_b,256,_ct.byref(_sr),None,None,None,0):\n"
        "    _v.append(str(_sr.value))\n"
        "  except Exception:pass\n"
        "  try:\n"
        "   import winreg as _wr\n"
        "   with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,'SOFTWARE\\\\Microsoft\\\\Cryptography') as _k:\n"
        "    _v.append(str(_wr.QueryValueEx(_k,'MachineGuid')[0]))\n"
        "  except Exception:pass\n"
        " elif _s=='Linux':\n"
        "  for _mp in ('/etc/machine-id','/var/lib/dbus/machine-id','/sys/class/dmi/id/product_uuid'):\n"
        "   try:\n"
        "    with open(_mp) as _mf:_v.append(_mf.read().strip()[:64]);break\n"
        "   except Exception:pass\n"
        " elif _s=='Darwin':\n"
        "  try:\n"
        "   import subprocess as _sp\n"
        "   _r=_sp.run(['ioreg','-rd1','-c','IOPlatformExpertDevice'],capture_output=True,text=True,timeout=2)\n"
        "   for _l in _r.stdout.splitlines():\n"
        "    if 'IOPlatformUUID' in _l and '\"' in _l:_v.append(_l.split('\"')[-2]);break\n"
        "  except Exception:pass\n"
        " return _h.sha256(('|'.join(x for x in _v if x) or str(_u.getnode())).encode('utf-8')).digest()\n"
    )


def get_hardware_fingerprint() -> bytes:
    ns: dict = {}
    exec(get_inline_hw_fp_src("_hw"), ns)
    return ns["_hw"]()


def new_crypto_meta(*, hw_bind: bool = False) -> dict:
    return {
        "salt": secrets.token_bytes(16),
        "aad": secrets.token_bytes(16),
        "perm_tag": secrets.token_bytes(8),
        "info_aes": secrets.token_bytes(8),
        "info_cc": secrets.token_bytes(8),
        "info_xor": secrets.token_bytes(8),
        "info_shuf": secrets.token_bytes(8),
        "hw_bind": hw_bind,
    }


def encrypt_payload_5layer(
    raw_bytes: bytes,
    *,
    outer_material: bytes = b"",
    hw_bind: bool = False,
    preset_meta: dict | None = None,
) -> dict:
    compressed = zlib.compress(raw_bytes, level=9)
    master_key = secrets.token_bytes(32)
    base = preset_meta if preset_meta is not None else new_crypto_meta(hw_bind=hw_bind)
    salt = base["salt"]
    aad = base["aad"]
    perm_tag = base["perm_tag"]
    info_aes = base["info_aes"]
    info_cc = base["info_cc"]
    info_xor = base["info_xor"]
    info_shuf = base["info_shuf"]
    hw_bind = bool(base.get("hw_bind", hw_bind))

    aes_key = hkdf(master_key, 32, salt + b"a", info_aes)
    cc_key = hkdf(master_key, 32, salt + b"c", info_cc)
    xor_key = hkdf(master_key, 16, salt + b"x", info_xor)
    shuf_key = hkdf(master_key, 16, salt + b"s", info_shuf)

    iv_aes, ct_aes, tag_aes = aes256_gcm_encrypt(aes_key, compressed, aad)
    aes_blob = iv_aes + tag_aes + ct_aes
    nonce_cc, ct_cc = chacha20_encrypt(aes_blob, cc_key)
    cc_blob = nonce_cc + ct_cc
    xs_data = xorshift_stream(cc_blob, xor_key)
    sh_data = byte_shuffle(xs_data, shuf_key, perm_tag)

    mask_material = salt + hashlib.sha256(outer_material).digest()
    mask = hashlib.sha256(mask_material).digest()
    if hw_bind:
        hw_mask = hashlib.sha256(get_hardware_fingerprint() + salt).digest()
        mask = bytes(a ^ b for a, b in zip(mask, hw_mask))
    stored_master = bytes(a ^ b for a, b in zip(master_key, mask))

    return {
        "ciphertext": sh_data,
        "stored_master": stored_master,
        "salt": salt,
        "aad": aad,
        "perm_tag": perm_tag,
        "info_aes": info_aes,
        "info_cc": info_cc,
        "info_xor": info_xor,
        "info_shuf": info_shuf,
        "hw_bind": hw_bind,
    }


def decrypt_payload_5layer(meta: dict, *, outer_material: bytes = b"") -> bytes:
    salt = meta["salt"]
    mask = hashlib.sha256(salt + hashlib.sha256(outer_material).digest()).digest()
    if meta.get("hw_bind"):
        hw_mask = hashlib.sha256(get_hardware_fingerprint() + salt).digest()
        mask = bytes(a ^ b for a, b in zip(mask, hw_mask))
    master_key = bytes(a ^ b for a, b in zip(meta["stored_master"], mask))
    aes_key = hkdf(master_key, 32, salt + b"a", meta["info_aes"])
    cc_key = hkdf(master_key, 32, salt + b"c", meta["info_cc"])
    xor_key = hkdf(master_key, 16, salt + b"x", meta["info_xor"])
    shuf_key = hkdf(master_key, 16, salt + b"s", meta["info_shuf"])

    s1 = byte_unshuffle(meta["ciphertext"], shuf_key, meta["perm_tag"])
    s2 = xorshift_unstream(s1, xor_key)
    s3 = chacha20_decrypt(s2[12:], cc_key, s2[:12])
    s4 = aes256_gcm_decrypt(aes_key, s3[:12], s3[28:], s3[12:28], meta["aad"])
    return zlib.decompress(s4)


def build_inline_decryptor_src(meta: dict, fn_name: str = "_strix_dec5") -> str:
    hw_src = get_inline_hw_fp_src("_hwfp") if meta.get("hw_bind") else ""
    hw_line = (
        " _m=bytes(a^b for a,b in zip(_m,_hh.sha256(_hwfp()+_sl).digest()))\n"
        if meta.get("hw_bind")
        else ""
    )
    sm_line = (
        f"_sm={meta['stored_master']!r}"
        if "stored_master" in meta
        else "_sm=_ct[:32];_ct=_ct[32:]"
    )
    return (
        f"{hw_src}"
        f"def {fn_name}(_ct,_mt):\n"
        " import hashlib as _hh,hmac as _hm,random as _rn,struct as _st,zlib as _zl\n"
        f" _sl={meta['salt']!r};{sm_line};_aad={meta['aad']!r};_pt={meta['perm_tag']!r}\n"
        " _m=_hh.sha256(_sl+_hh.sha256(_mt).digest()).digest()\n"
        f"{hw_line}"
        " _mk=bytes(a^b for a,b in zip(_sm,_m))\n"
        " def _hk(s,inf,ln):\n"
        "  p=_hm.new(s,_mk,_hh.sha256).digest();t=b'';o=bytearray();i=1\n"
        "  while len(o)<ln:t=_hm.new(p,t+inf+bytes([i]),_hh.sha256).digest();o.extend(t);i+=1\n"
        "  return bytes(o[:ln])\n"
        f" _ak=_hk(_sl+b'a',{meta['info_aes']!r},32);_ck=_hk(_sl+b'c',{meta['info_cc']!r},32)\n"
        f" _xk=_hk(_sl+b'x',{meta['info_xor']!r},16);_sk=_hk(_sl+b's',{meta['info_shuf']!r},16)\n"
        " _n=len(_ct);_rg=_rn.Random(int.from_bytes(_hh.sha256(_sk+_pt).digest()[:8],'big'))\n"
        " _ix=list(range(_n));_rg.shuffle(_ix);_s1=bytearray(_n)\n"
        " for _np,_op in enumerate(_ix):_s1[_op]=_ct[_np]\n"
        " _x=int.from_bytes(_xk[:8],'big') or 0xDEADBEEFCAFEBABE;_s2=bytearray(_n)\n"
        " for _i,_b in enumerate(_s1):\n"
        "  _x^=(_x<<13)&0xFFFFFFFFFFFFFFFF;_x^=_x>>7;_x^=(_x<<17)&0xFFFFFFFFFFFFFFFF;_s2[_i]=_b^(_x&0xFF)\n"
        " def _cq(a,b,c,d):\n"
        "  a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<16)|(d>>16))&0xFFFFFFFF\n"
        "  c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<12)|(b>>20))&0xFFFFFFFF\n"
        "  a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<8)|(d>>24))&0xFFFFFFFF\n"
        "  c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<7)|(b>>25))&0xFFFFFFFF\n"
        "  return a,b,c,d\n"
        " _nc=_s2[:12];_c2=_s2[12:];_s3=bytearray()\n"
        " _cs=list(_st.unpack('<4I',b'expand 32-byte k'))+list(_st.unpack('<8I',_ck))\n"
        " _ns=list(_st.unpack('<3I',_nc))\n"
        " for _bi,_of in enumerate(range(0,len(_c2),64)):\n"
        "  _st0=_cs+[_bi]+_ns;_w=_st0[:]\n"
        "  for _ in range(10):\n"
        "   _w[0],_w[4],_w[8],_w[12]=_cq(_w[0],_w[4],_w[8],_w[12]);_w[1],_w[5],_w[9],_w[13]=_cq(_w[1],_w[5],_w[9],_w[13])\n"
        "   _w[2],_w[6],_w[10],_w[14]=_cq(_w[2],_w[6],_w[10],_w[14]);_w[3],_w[7],_w[11],_w[15]=_cq(_w[3],_w[7],_w[11],_w[15])\n"
        "   _w[0],_w[5],_w[10],_w[15]=_cq(_w[0],_w[5],_w[10],_w[15]);_w[1],_w[6],_w[11],_w[12]=_cq(_w[1],_w[6],_w[11],_w[12])\n"
        "   _w[2],_w[7],_w[8],_w[13]=_cq(_w[2],_w[7],_w[8],_w[13]);_w[3],_w[4],_w[9],_w[14]=_cq(_w[3],_w[4],_w[9],_w[14])\n"
        "  _ks=_st.pack('<16I',*((_w[_j]+_st0[_j])&0xFFFFFFFF for _j in range(16)))\n"
        "  _s3.extend(b^k for b,k in zip(_c2[_of:_of+64],_ks))\n"
        f" _sb={list(_AES_SBOX)!r};_rc={list(_AES_RCON)!r}\n"
        " _xt=[((i<<1)^0x1B)&0xFF if i&0x80 else (i<<1)&0xFF for i in range(256)]\n"
        " _w=list(_ak)\n"
        " for _i in range(8,60):\n"
        "  _t0,_t1,_t2,_t3=_w[(_i-1)*4:_i*4]\n"
        "  if _i%8==0:_t0,_t1,_t2,_t3=_sb[_t1]^_rc[_i//8-1],_sb[_t2],_sb[_t3],_sb[_t0]\n"
        "  elif _i%8==4:_t0,_t1,_t2,_t3=_sb[_t0],_sb[_t1],_sb[_t2],_sb[_t3]\n"
        "  _bs=(_i-8)*4;_w.extend((_w[_bs]^_t0,_w[_bs+1]^_t1,_w[_bs+2]^_t2,_w[_bs+3]^_t3))\n"
        " _rks=[_w[16*r:16*(r+1)] for r in range(15)]\n"
        " def _ab(blk):\n"
        "  s=list(blk);rk0=_rks[0]\n"
        "  for i in range(16):s[i]^=rk0[i]\n"
        "  for rnd in range(1,14):\n"
        "   s=[_sb[b] for b in s]\n"
        "   s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1];s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6];s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]\n"
        "   rk=_rks[rnd]\n"
        "   for c in (0,4,8,12):\n"
        "    a0,a1,a2,a3=s[c],s[c+1],s[c+2],s[c+3];x0,x1,x2,x3=_xt[a0],_xt[a1],_xt[a2],_xt[a3]\n"
        "    s[c]=x0^x1^a1^a2^a3^rk[c];s[c+1]=a0^x1^x2^a2^a3^rk[c+1];s[c+2]=a0^a1^x2^x3^a3^rk[c+2];s[c+3]=x0^a0^a1^a2^x3^rk[c+3]\n"
        "  s=[_sb[b] for b in s]\n"
        "  s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1];s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6];s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]\n"
        "  rk14=_rks[14]\n"
        "  for i in range(16):s[i]^=rk14[i]\n"
        "  return bytes(s)\n"
        " _hi=int.from_bytes(_ab(b'\\x00'*16),'big');_iv=bytes(_s3[:12]);_tg=bytes(_s3[12:28]);_ca=bytes(_s3[28:])\n"
        " def _p16(d):r=len(d)&15;return d+b'\\x00'*(16-r) if r else d\n"
        " _gd=_p16(_aad)+_p16(_ca)+_st.pack('>QQ',len(_aad)*8,len(_ca)*8);_y=0\n"
        " for _i in range(0,len(_gd),16):\n"
        "  _x=_y^int.from_bytes(_gd[_i:_i+16],'big');_v=_hi;_z=0\n"
        "  for _b in range(127,-1,-1):\n"
        "   if (_x>>_b)&1:_z^=_v\n"
        "   _v=((_v>>1)^(0xE1<<120)) if (_v&1) else (_v>>1)\n"
        "  _y=_z\n"
        " _et=bytes(a^b for a,b in zip(_y.to_bytes(16,'big'),_ab(_iv+b'\\x00\\x00\\x00\\x01')))\n"
        " if not _hm.compare_digest(_et,_tg):raise ValueError\n"
        " _ptx=bytearray()\n"
        " for _i in range(0,len(_ca),16):\n"
        "  _ks=_ab(_iv+_st.pack('>I',_i//16+2));_ptx.extend(b^k for b,k in zip(_ca[_i:_i+16],_ks))\n"
        " return _zl.decompress(bytes(_ptx))\n"
    )
