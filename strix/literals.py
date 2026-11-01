# Copyright (c) 2026 w0otdev (Strix modifications)
# Licensed under the Apache License, Version 2.0.

"""Per-occurrence literal encoding for the full and mega compilation modes."""

import ast
import secrets
import struct

from .context import make_ks


def harden_literals(source: str, *, fragment: bool = False) -> str:
    tree = ast.parse(source)
    identifiers = {
        value
        for node in ast.walk(tree)
        for _, value in ast.iter_fields(node)
        if isinstance(value, str)
    }

    def fresh_name() -> str:
        while True:
            name = "_" + secrets.token_hex(12)
            if name not in identifiers:
                identifiers.add(name)
                return name

    decoder = fresh_name()
    number = fresh_name()
    key = secrets.token_bytes(32)
    used_binary = False
    used_number = False

    class Literals(ast.NodeTransformer):
        def visit_Module(self, node: ast.Module):
            return self.visit_body(node)

        def visit_FunctionDef(self, node: ast.FunctionDef):
            return self.visit_body(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            return self.visit_body(node)

        def visit_ClassDef(self, node: ast.ClassDef):
            return self.visit_body(node)

        def visit_body(self, node):
            # A docstring is metadata rather than an executable expression.
            docstring = None
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                docstring = node.body.pop(0)
            self.generic_visit(node)
            if docstring is not None:
                node.body.insert(0, docstring)
            return node

        def visit_Constant(self, node: ast.Constant):
            nonlocal used_binary, used_number
            value = node.value
            if isinstance(value, bool) or value is None or value is Ellipsis:
                return node
            if isinstance(value, int):
                used_number = True
                mask = secrets.randbits(64) | 1
                offset = secrets.randbits(64) | 1
                variant = secrets.randbelow(4)
                if variant == 0:
                    encoded = (value + offset) ^ mask
                elif variant == 1:
                    encoded = (value ^ mask) + offset
                elif variant == 2:
                    encoded = (value ^ mask) - offset
                else:
                    encoded = (value ^ mask) ^ offset
                return ast.copy_location(
                    ast.Call(
                        func=ast.Name(id=number, ctx=ast.Load()),
                        args=[
                            ast.Constant(v) for v in (encoded, mask, offset, variant)
                        ],
                        keywords=[],
                    ),
                    node,
                )

            if isinstance(value, str):
                data, kind = value.encode("utf-8", "surrogatepass"), 0
            elif isinstance(value, bytes):
                data, kind = value, 1
            elif isinstance(value, float):
                data, kind = struct.pack(">d", value), 2
            elif isinstance(value, complex):
                data, kind = struct.pack(">dd", value.real, value.imag), 3
            else:
                return node

            used_binary = True
            nonce = secrets.token_bytes(16)
            stream = make_ks(key + nonce, len(data))
            encrypted = bytes(a ^ b for a, b in zip(data, stream, strict=True))
            size = 12 + secrets.randbelow(29) if fragment else 128
            chunks = [encrypted[i : i + size] for i in range(0, len(encrypted), size)]
            positions = list(range(len(chunks)))
            if fragment:
                secrets.SystemRandom().shuffle(positions)
            inverse = [0] * len(positions)
            for position, original in enumerate(positions):
                inverse[original] = position
            return ast.copy_location(
                ast.Call(
                    func=ast.Name(id=decoder, ctx=ast.Load()),
                    args=[
                        ast.Tuple(
                            elts=[
                                ast.Constant(
                                    int.from_bytes(bytes([1]) + chunks[i], "big")
                                )
                                for i in positions
                            ],
                            ctx=ast.Load(),
                        ),
                        ast.Tuple(
                            elts=[ast.Constant(i) for i in inverse], ctx=ast.Load()
                        ),
                        ast.Constant(int.from_bytes(nonce, "big")),
                        ast.Constant(kind),
                    ],
                    keywords=[],
                ),
                node,
            )

        _spec_depth = 0

        def visit_FormattedValue(self, node: ast.FormattedValue):
            node.value = self.visit(node.value)
            if node.format_spec is not None:
                self._spec_depth += 1
                try:
                    node.format_spec = self.visit(node.format_spec)
                finally:
                    self._spec_depth -= 1
            return node

        def visit_JoinedStr(self, node: ast.JoinedStr):
            # Keep f-string grammar and conversions, including nested format specs.
            can_wrap = self._spec_depth == 0 or (
                self._spec_depth == 1
                and not any(isinstance(v, ast.FormattedValue) for v in node.values)
            )
            values = []
            for item in node.values:
                if isinstance(item, ast.Constant) and can_wrap:
                    values.append(
                        ast.FormattedValue(
                            value=self.visit(item), conversion=-1, format_spec=None
                        )
                    )
                elif isinstance(item, ast.Constant):
                    values.append(item)
                else:
                    values.append(self.visit(item))
            node.values = values
            return node

        def visit_MatchValue(self, node: ast.MatchValue):
            # Python patterns require literals, rather than calls to a decoder.
            return node

        def visit_MatchMapping(self, node: ast.MatchMapping):
            node.patterns = [self.visit(pattern) for pattern in node.patterns]
            return node

    tree = Literals().visit(tree)
    helpers = []
    if used_binary:
        helpers.extend(
            ast.parse(
                f"""
def {decoder}(_parts, _order, _nonce, _kind,
    _key={key!r}, _hash=__import__('hashlib').sha256,
    _unpack=__import__('struct').unpack, _bytes=bytes, _len=len,
    _range=range, _enumerate=enumerate, _complex=complex):
    _data = b''.join(_parts[_i].to_bytes((_parts[_i].bit_length() + 7) // 8, 'big')[1:]
        for _i in _order)
    _nonce = _nonce.to_bytes(16, 'big')
    _stream = b''.join(_hash(_key + _nonce + _i.to_bytes(8, 'big')).digest()
        for _i in _range((_len(_data) + 31) // 32))
    _raw = _bytes(_v ^ _stream[_i] for _i, _v in _enumerate(_data))
    if _kind == 0:
        return _raw.decode('utf-8', 'surrogatepass')
    if _kind == 1:
        return _raw
    if _kind == 2:
        return _unpack('>d', _raw)[0]
    return _complex(*_unpack('>dd', _raw))
"""
            ).body
        )
    if used_number:
        helpers.extend(
            ast.parse(
                f"""
def {number}(_value, _mask, _offset, _variant):
    if _variant == 0:
        return ((_value + _mask) - ((_value & _mask) << 1)) - _offset
    if _variant == 1:
        _t = _value - _offset
        return (_t + _mask) - ((_t & _mask) << 1)
    if _variant == 2:
        _t = _value + _offset
        return (_t + _mask) - ((_t & _mask) << 1)
    _t = (_value + _offset) - ((_value & _offset) << 1)
    return (_t + _mask) - ((_t & _mask) << 1)
"""
            ).body
        )

    # Randomize helper locals too; public attribute names stay unchanged.
    local_names = {}

    def local_name(name: str) -> str:
        if name not in local_names:
            local_names[name] = fresh_name()
        return local_names[name]

    for helper in helpers:
        for node in ast.walk(helper):
            if (
                isinstance(node, ast.Name)
                and node.id.startswith("_")
                and node.id != "__import__"
            ):
                node.id = local_name(node.id)
            elif isinstance(node, ast.arg):
                node.arg = local_name(node.arg)

    # Keep a module docstring and future imports in their required positions.
    insertion = 1 if ast.get_docstring(tree) is not None else 0
    for node in tree.body[insertion:]:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            insertion += 1
        else:
            break
    tree.body[insertion:insertion] = helpers
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)
