# Copyright (c) 2026 w0otdev (Strix modifications)
# Original work Copyright (c) ktn1703 (https://github.com/ktn1703/Neo)
# Licensed under the Apache License, Version 2.0.
# Modified by w0otdev: Modularized and rebranded under Strix.

import ast
import random

from .context import (
    BUILTINS,
    HIDE_LIST,
    I_,
    QN,
    B,
    F,
    I,
    S,
    hz,
    rand_confuse_name,
)


def anti_pycdc_block():
    e = {
        "Z": "1/0,",
        "T": "len+1,",
        "N": "xyz,",
        "T2": '"a"+1,',
        "I": "[][99],",
        "K": '{}[""],',
        "M": "__import__('xyz'),",
        "V": 'int("a",99),',
        "A": "[].__x,",
        "F": 'open("ww"),',
        "G": "0 if False else 1//0,",
        "H": 'f"{[0]}" and (1//0),',
        "Q": "{}.get(0) and 1//0,",
        "W": "not 0 or [][99],",
    }
    ct = max(60, min(250, 1200 // len(e)))
    for k, value in e.items():
        e[k] = value * ct
    block = "\n".join(f"try:({v})\nexcept:0" for v in e.values())
    return "\ntry:pass\nexcept:pass\nelse:pass\nfinally:pass\n" + block + "\n"


def clean_try_except(source):
    try:
        t = ast.parse(source)
        prefix = []
        if ast.get_docstring(t) is not None:
            prefix.append(t.body.pop(0))
        while (
            t.body
            and isinstance(t.body[0], ast.ImportFrom)
            and t.body[0].module == "__future__"
        ):
            prefix.append(t.body.pop(0))
        body = t.body or [ast.Pass()]
        try_except = ast.Try(
            body=body,
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id="KeyboardInterrupt", ctx=ast.Load()),
                    name=None,
                    body=[
                        ast.Expr(
                            ast.Call(
                                func=ast.Name(id="print", ctx=ast.Load()),
                                args=[ast.Constant(value="\n\nExiting...")],
                                keywords=[],
                            )
                        ),
                        ast.Raise(
                            exc=ast.Call(
                                func=ast.Name(id="SystemExit", ctx=ast.Load()),
                                args=[ast.Constant(value=0)],
                                keywords=[],
                            ),
                            cause=None,
                        ),
                    ],
                ),
            ],
            orelse=[],
            finalbody=[],
        )
        m = ast.Module(body=[*prefix, try_except], type_ignores=[])
        ast.fix_missing_locations(m)
        return ast.unparse(m)
    except SyntaxError:
        return source


def joinstr(f):
    if not isinstance(f, ast.JoinedStr):
        return f
    vl = []
    for i in f.values:
        if isinstance(i, ast.Constant):
            if isinstance(i.value, str):
                vl.append(i)
            else:
                vl.append(ast.Constant(value=str(i.value)))
        elif isinstance(i, ast.FormattedValue):
            value_expr = i.value
            if i.conversion == 115:
                value_expr = ast.Call(
                    func=ast.Name(id="str", ctx=ast.Load()),
                    args=[value_expr],
                    keywords=[],
                )
            elif i.conversion == 114:
                value_expr = ast.Call(
                    func=ast.Name(id="repr", ctx=ast.Load()),
                    args=[value_expr],
                    keywords=[],
                )
            elif i.conversion == 97:
                value_expr = ast.Call(
                    func=ast.Name(id="ascii", ctx=ast.Load()),
                    args=[value_expr],
                    keywords=[],
                )
            elif not i.format_spec:
                value_expr = ast.Call(
                    func=ast.Name(id="str", ctx=ast.Load()),
                    args=[value_expr],
                    keywords=[],
                )
            if i.format_spec:
                spec = i.format_spec
                value_expr = ast.Call(
                    func=ast.Name(id="format", ctx=ast.Load()),
                    args=[value_expr, spec],
                    keywords=[],
                )
            vl.append(value_expr)
        else:
            vl.append(i)
    if not vl:
        return ast.Constant(value="")
    if len(vl) == 1 and isinstance(vl[0], ast.Constant):
        return vl[0]
    return ast.Call(
        func=ast.Attribute(value=ast.Constant(value=""), attr="join", ctx=ast.Load()),
        args=[ast.Tuple(elts=vl, ctx=ast.Load())],
        keywords=[],
    )


class Cv(ast.NodeTransformer):
    def visit_JoinedStr(self, node):
        return joinstr(node)


def _fn_param_names(fn_node) -> set[str]:
    names = {
        arg.arg
        for arg in (
            *fn_node.args.posonlyargs,
            *fn_node.args.args,
            *fn_node.args.kwonlyargs,
        )
    }
    if fn_node.args.vararg:
        names.add(fn_node.args.vararg.arg)
    if fn_node.args.kwarg:
        names.add(fn_node.args.kwarg.arg)
    return names


def _has_annotations(fn_node) -> bool:
    if fn_node.returns is not None:
        return True
    all_args = [
        *fn_node.args.posonlyargs,
        *fn_node.args.args,
        *fn_node.args.kwonlyargs,
    ]
    if fn_node.args.vararg:
        all_args.append(fn_node.args.vararg)
    if fn_node.args.kwarg:
        all_args.append(fn_node.args.kwarg)
    return any(arg.annotation is not None for arg in all_args)


def obf_vars(source, *, use_confuse: bool = True):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(n.name == "*" for n in node.names):
            return source

    gen_name = rand_confuse_name if use_confuse else hz

    module_names = set()
    declared = set()
    method_names = set()
    attr_names = set()
    kwarg_names = set()
    decorated_fn_names = set()
    annotated_param_names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                module_names.add(a.name.split(".")[0])
                if a.asname:
                    module_names.add(a.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module_names.add(node.module.split(".")[0])
            for a in node.names:
                if a.asname:
                    module_names.add(a.asname)
                else:
                    module_names.add(a.name)
        elif isinstance(node, ast.Attribute):
            attr_names.add(node.attr)
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg:
                    kwarg_names.add(kw.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            declared.add(node.name)
            if node.decorator_list:
                decorated_fn_names.add(node.name)
            if _has_annotations(node):
                annotated_param_names.update(_fn_param_names(node))
        elif isinstance(node, ast.ClassDef):
            declared.add(node.name)
            if node.decorator_list:
                decorated_fn_names.add(node.name)
        elif isinstance(node, ast.arg):
            declared.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            declared.add(node.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            declared.update(node.names)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                declared.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name:
                declared.add(node.name)
        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                declared.add(node.rest)

    for parent in ast.walk(tree):
        if isinstance(parent, ast.ClassDef):
            for sub in parent.body:
                if isinstance(
                    sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    method_names.add(sub.name)
                elif isinstance(sub, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = (
                        sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                    )
                    for t in targets:
                        for n in ast.walk(t):
                            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                                method_names.add(n.id)

    not_rename = (
        attr_names
        | kwarg_names
        | method_names
        | decorated_fn_names
    )

    def _can_rename(name, is_local=False):
        if name in module_names or name in BUILTINS:
            return False
        if name.startswith("__") or name in ("self", "cls", "_"):
            return False
        if is_local:
            return (
                name not in kwarg_names
                and name not in method_names
                and name not in decorated_fn_names
            )
        return name not in not_rename

    aliases = {name: gen_name() for name in declared if _can_rename(name)}

    def _fn_locals(fn_node):
        bound = set()
        shared = set()
        stack = list(fn_node.body)
        for arg in (
            *fn_node.args.posonlyargs,
            *fn_node.args.args,
            *fn_node.args.kwonlyargs,
        ):
            bound.add(arg.arg)
        if fn_node.args.vararg:
            bound.add(fn_node.args.vararg.arg)
        if fn_node.args.kwarg:
            bound.add(fn_node.args.kwarg.arg)
        while stack:
            cur = stack.pop()
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(cur.name)
                continue
            if isinstance(cur, (ast.Global, ast.Nonlocal)):
                shared.update(cur.names)
            elif isinstance(cur, ast.Name) and isinstance(cur.ctx, ast.Store):
                bound.add(cur.id)
            elif isinstance(cur, ast.ExceptHandler) and cur.name:
                bound.add(cur.name)
            elif isinstance(cur, (ast.MatchAs, ast.MatchStar)) and cur.name:
                bound.add(cur.name)
            elif isinstance(cur, ast.MatchMapping) and cur.rest:
                bound.add(cur.rest)
            stack.extend(ast.iter_child_nodes(cur))
        return bound - shared

    class Ren(ast.NodeTransformer):
        def __init__(self, scope):
            self.scope = scope

        def visit_Name(self, node):
            if node.id in self.scope:
                node.id = self.scope[node.id]
            return node

        def _visit_fn(self, node):
            if not node.decorator_list and node.name in self.scope:
                node.name = self.scope[node.name]
            node.decorator_list = [self.visit(d) for d in node.decorator_list]
            node.args.defaults = [self.visit(d) for d in node.args.defaults]
            node.args.kw_defaults = [
                self.visit(d) if d is not None else None for d in node.args.kw_defaults
            ]
            if node.returns is not None:
                node.returns = self.visit(node.returns)
            for a in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *([node.args.vararg] if node.args.vararg else []),
                *([node.args.kwarg] if node.args.kwarg else []),
            ):
                if a.annotation is not None:
                    a.annotation = self.visit(a.annotation)

            locked_params = _fn_param_names(node) if _has_annotations(node) else set()
            child_scope = dict(self.scope)
            for name in _fn_locals(node):
                if name not in locked_params and _can_rename(name, is_local=True):
                    child_scope[name] = gen_name()
                else:
                    child_scope.pop(name, None)
            prev = self.scope
            self.scope = child_scope
            try:
                for a in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                    *([node.args.vararg] if node.args.vararg else []),
                    *([node.args.kwarg] if node.args.kwarg else []),
                ):
                    if a.arg in self.scope:
                        a.arg = self.scope[a.arg]
                node.body = [self.visit(stmt) for stmt in node.body]
            finally:
                self.scope = prev
            return node

        def visit_FunctionDef(self, node):
            return self._visit_fn(node)

        def visit_AsyncFunctionDef(self, node):
            return self._visit_fn(node)

        def visit_ClassDef(self, node):
            if not node.decorator_list and node.name in self.scope:
                node.name = self.scope[node.name]
            node.bases = [self.visit(b) for b in node.bases]
            node.keywords = [self.visit(k) for k in node.keywords]
            node.decorator_list = [self.visit(d) for d in node.decorator_list]
            node.body = [
                self.visit(sub)
                if isinstance(
                    sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
                else sub
                for sub in node.body
            ]
            return node

        def visit_arg(self, node):
            if node.arg in self.scope:
                node.arg = self.scope[node.arg]
            return node

        def visit_Global(self, node):
            node.names = [self.scope.get(x, x) for x in node.names]
            return node

        def visit_Nonlocal(self, node):
            node.names = [self.scope.get(x, x) for x in node.names]
            return node

        def visit_ExceptHandler(self, node):
            if node.name and node.name in self.scope:
                node.name = self.scope[node.name]
            self.generic_visit(node)
            return node

        def visit_MatchAs(self, node):
            if node.name and node.name in self.scope:
                node.name = self.scope[node.name]
            self.generic_visit(node)
            return node

        def visit_MatchStar(self, node):
            if node.name and node.name in self.scope:
                node.name = self.scope[node.name]
            return node

        def visit_MatchMapping(self, node):
            if node.rest and node.rest in self.scope:
                node.rest = self.scope[node.rest]
            self.generic_visit(node)
            return node

    tree = Ren(aliases).visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def hide_builtins(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    # Conservatively keep any name bound by the script, even in a nested scope.
    bound = {"super"}  # A direct super() load creates the compiler's __class__ cell.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.alias):
            if node.name == "*":
                return source
            bound.add(node.asname or node.name.split(".")[0])
        elif (isinstance(node, ast.ExceptHandler) and node.name) or (
            isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name
        ):
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)

    class Hide(ast.NodeTransformer):
        def visit_MatchClass(self, node):
            node.patterns = [self.visit(p) for p in node.patterns]
            node.kwd_patterns = [self.visit(p) for p in node.kwd_patterns]
            return node

        def visit_Name(self, node):
            if (
                isinstance(node.ctx, ast.Load)
                and node.id in HIDE_LIST
                and node.id not in bound
            ):
                return ast.copy_location(
                    ast.parse(f"{QN('bd')}[{S(node.id)}]", mode="eval").body, node
                )
            return node

    tree = Hide().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def obf_consts(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class Constants(ast.NodeTransformer):
        def visit_Constant(self, node):
            value = node.value
            expression = None
            if isinstance(value, str):
                expression = S(value)
            elif isinstance(value, bool):
                return node
            elif isinstance(value, int):
                expression = I(value)
            elif isinstance(value, float):
                expression = F(value)
            elif isinstance(value, bytes):
                expression = B(value)
            if expression is None:
                return node
            return ast.copy_location(ast.parse(expression, mode="eval").body, node)

        def visit_JoinedStr(self, node):
            return self.visit(joinstr(node))

        def visit_MatchValue(self, node):
            # Literal patterns cannot contain decoder calls.
            return node

        def visit_MatchMapping(self, node):
            node.patterns = [self.visit(pattern) for pattern in node.patterns]
            return node

    tree = Constants().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def junk_cases(en, max_value):
    cases = []
    line = max_value + 1
    for _ in range(random.randint(1, 4)):
        case_name = hz()
        cases.append(
            ast.If(
                test=ast.Compare(
                    left=ast.Subscript(
                        value=ast.Attribute(value=ast.Name(id=en), attr="args"),
                        slice=ast.Constant(value=0),
                    ),
                    ops=[ast.Eq()],
                    comparators=[ast.parse(I_(line), mode="eval").body],
                ),
                body=[
                    ast.Assign(
                        targets=[ast.Name(id=case_name, ctx=ast.Store())],
                        value=ast.parse(
                            I_(random.randint(0xFFFFF, 0xFFFFFFFFFFFF)), mode="eval"
                        ).body,
                    )
                ],
                orelse=[],
            )
        )
        line += 1
    return cases


def bl(body):
    var = hz()
    en = hz()
    tb = [
        ast.AugAssign(
            target=ast.Name(id=var, ctx=ast.Store()),
            op=ast.Add(),
            value=ast.parse(I_(1), mode="eval").body,
        ),
        ast.Try(
            body=[
                ast.Raise(
                    exc=ast.Call(
                        func=ast.Name(id="MemoryError", ctx=ast.Load()),
                        args=[ast.Name(id=var, ctx=ast.Load())],
                        keywords=[],
                    )
                )
            ],
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id="MemoryError", ctx=ast.Load()), name=en, body=[]
                )
            ],
            orelse=[],
            finalbody=[],
        ),
    ]
    for i in body:
        tb[1].handlers[0].body.append(
            ast.If(
                test=ast.Compare(
                    left=ast.Subscript(
                        value=ast.Attribute(
                            value=ast.Name(id=en, ctx=ast.Load()), attr="args"
                        ),
                        slice=ast.Constant(value=0),
                    ),
                    ops=[ast.Eq()],
                    comparators=[ast.parse(I_(1), mode="eval").body],
                ),
                body=[i],
                orelse=[],
            )
        )
    tb[1].handlers[0].body.extend(junk_cases(en, len(body) + 1))
    node = ast.Assign(
        targets=[ast.Name(id=var, ctx=ast.Store())],
        value=ast.parse(I_(0), mode="eval").body,
    )
    return [node, *tb]


def _bl(node):
    olb = node.body
    docstring = []
    if (
        olb
        and isinstance(olb[0], ast.Expr)
        and isinstance(olb[0].value, ast.Constant)
        and isinstance(olb[0].value.value, str)
    ):
        docstring = [olb[0]]
        olb = olb[1:]
    node.body = [*docstring, *bl(olb)]
    return node


def process_block(block):
    nb = []
    for node in block:
        if (
            not nb
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            nb.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nb.append(_bl(node))
        elif isinstance(node, ast.ClassDef):
            node.body = [
                _bl(m) if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) else m
                for m in node.body
            ]
            nb.append(node)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr)):
            nb.extend(bl([node]))
        elif isinstance(node, ast.Try):
            node.body = process_block(node.body)
            for handler in node.handlers:
                handler.body = process_block(handler.body)
            if node.orelse:
                node.orelse = process_block(node.orelse)
            if node.finalbody:
                node.finalbody = process_block(node.finalbody)
            nb.append(node)
        else:
            nb.append(node)
    return nb


def spam(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    tree.body = process_block(tree.body)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def _safe_insert_index(tree: ast.Module) -> int:
    idx = 1 if ast.get_docstring(tree, clean=False) is not None else 0
    while (
        idx < len(tree.body)
        and isinstance(tree.body[idx], ast.ImportFrom)
        and tree.body[idx].module == "__future__"
    ):
        idx += 1
    return idx


class IntObfuscator(ast.NodeTransformer):
    def visit_MatchValue(self, node):
        return node

    def visit_MatchSingleton(self, node):
        return node

    def visit_MatchSequence(self, node):
        return node

    def visit_MatchMapping(self, node):
        return node

    def visit_MatchClass(self, node):
        return node

    def visit_MatchStar(self, node):
        return node

    def visit_MatchAs(self, node):
        return node

    def visit_MatchOr(self, node):
        return node

    def visit_Constant(self, node: ast.Constant):
        if (
            isinstance(node.value, int)
            and not isinstance(node.value, bool)
            and 0 < abs(node.value) <= 0xFFFFFFFF
        ):
            v = abs(node.value)
            a = random.randint(1, 0xFFFF)
            scheme = random.randint(0, 3)
            if scheme == 0:
                b = v ^ a
                expr = ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Constant(value=a),
                        op=ast.Add(),
                        right=ast.Constant(value=b),
                    ),
                    op=ast.Sub(),
                    right=ast.BinOp(
                        left=ast.Constant(value=2),
                        op=ast.Mult(),
                        right=ast.BinOp(
                            left=ast.Constant(value=a),
                            op=ast.BitAnd(),
                            right=ast.Constant(value=b),
                        ),
                    ),
                )
            elif scheme == 1:
                b = v ^ a
                expr = ast.BinOp(
                    left=ast.Constant(value=a),
                    op=ast.BitXor(),
                    right=ast.Constant(value=b),
                )
            elif scheme == 2:
                k = random.randint(2, 127)
                c = a * k - v
                expr = ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Constant(value=a),
                        op=ast.Mult(),
                        right=ast.Constant(value=k),
                    ),
                    op=ast.Sub(),
                    right=ast.Constant(value=c),
                )
            else:
                a2 = v & random.randint(1, 0xFFFFFFFF)
                b2 = v
                expr = ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Constant(value=a2),
                        op=ast.Add(),
                        right=ast.Constant(value=b2),
                    ),
                    op=ast.Sub(),
                    right=ast.BinOp(
                        left=ast.Constant(value=a2),
                        op=ast.BitAnd(),
                        right=ast.Constant(value=b2),
                    ),
                )
            if node.value < 0:
                expr = ast.UnaryOp(op=ast.USub(), operand=expr)
            return ast.copy_location(expr, node)
        return node


class StringEncryptor(ast.NodeTransformer):
    def __init__(self):
        self._docstring_ids: set[int] = set()
        self._spec_depth = 0
        self._used = False
        self._b_bytes = rand_confuse_name()
        self._b_enum = rand_confuse_name()
        self._b_zip = rand_confuse_name()
        self._b_rev = rand_confuse_name()

    def _collect_docstrings(self, tree: ast.AST) -> None:
        for sub in ast.walk(tree):
            if isinstance(
                sub,
                (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                if (
                    sub.body
                    and isinstance(sub.body[0], ast.Expr)
                    and isinstance(sub.body[0].value, ast.Constant)
                    and isinstance(sub.body[0].value.value, str)
                ):
                    self._docstring_ids.add(id(sub.body[0].value))

    def visit_Module(self, node: ast.Module):
        self._collect_docstrings(node)
        self.generic_visit(node)
        if self._used:
            alias_stmt = ast.Assign(
                targets=[
                    ast.Tuple(
                        elts=[
                            ast.Name(id=self._b_bytes, ctx=ast.Store()),
                            ast.Name(id=self._b_enum, ctx=ast.Store()),
                            ast.Name(id=self._b_zip, ctx=ast.Store()),
                            ast.Name(id=self._b_rev, ctx=ast.Store()),
                        ],
                        ctx=ast.Store(),
                    )
                ],
                value=ast.Tuple(
                    elts=[
                        ast.Name(id="bytes", ctx=ast.Load()),
                        ast.Name(id="enumerate", ctx=ast.Load()),
                        ast.Name(id="zip", ctx=ast.Load()),
                        ast.Name(id="reversed", ctx=ast.Load()),
                    ],
                    ctx=ast.Load(),
                ),
            )
            idx = _safe_insert_index(node)
            node.body.insert(idx, alias_stmt)
            ast.fix_missing_locations(node)
        return node

    def _xor_pos(self, raw: bytes) -> ast.expr:
        key = random.randint(1, 254)
        enc = [(b ^ key ^ (i & 0xFF)) & 0xFF for i, b in enumerate(raw)]
        iv = rand_confuse_name(8)
        vv = rand_confuse_name(8)
        code = (
            f"{self._b_bytes}(({vv} ^ {key} ^ ({iv} & 255)) & 255 "
            f"for {iv}, {vv} in {self._b_enum}({enc!r})).decode('utf-8', 'surrogatepass')"
        )
        return ast.parse(code, mode="eval").body

    def _xor_rev(self, raw: bytes) -> ast.expr:
        key = random.randint(1, 254)
        enc = list(reversed([(b ^ key) & 0xFF for b in raw]))
        vv = rand_confuse_name(8)
        code = (
            f"{self._b_bytes}(({vv} ^ {key}) & 255 "
            f"for {vv} in {self._b_rev}({enc!r})).decode('utf-8', 'surrogatepass')"
        )
        return ast.parse(code, mode="eval").body

    def _xor_split(self, raw: bytes) -> ast.expr:
        k_list = [random.randint(1, 254) for _ in raw]
        d_list = [(b ^ k) & 0xFF for b, k in zip(raw, k_list)]
        vv = rand_confuse_name(8)
        kv = rand_confuse_name(8)
        code = (
            f"{self._b_bytes}(({vv} ^ {kv}) & 255 "
            f"for {vv}, {kv} in {self._b_zip}({d_list!r}, {k_list!r})).decode('utf-8', 'surrogatepass')"
        )
        return ast.parse(code, mode="eval").body

    def _rc4_scheme(self, raw: bytes) -> ast.expr:
        k0 = random.randint(1, 254)
        k1 = random.randint(1, 254) | 1
        enc = [(b ^ ((i * k1 + k0) ^ (i >> 2))) & 0xFF for i, b in enumerate(raw)]
        iv = rand_confuse_name(8)
        vv = rand_confuse_name(8)
        code = (
            f"{self._b_bytes}(({vv} ^ (({iv} * {k1} + {k0}) ^ ({iv} >> 2))) & 255 "
            f"for {iv}, {vv} in {self._b_enum}({enc!r})).decode('utf-8', 'surrogatepass')"
        )
        return ast.parse(code, mode="eval").body

    def _modadd_scheme(self, raw: bytes) -> ast.expr:
        key = random.randint(1, 254)
        enc = [(b + key + i) & 0xFF for i, b in enumerate(raw)]
        iv = rand_confuse_name(8)
        vv = rand_confuse_name(8)
        code = (
            f"{self._b_bytes}(({vv} - {key} - {iv}) & 255 "
            f"for {iv}, {vv} in {self._b_enum}({enc!r})).decode('utf-8', 'surrogatepass')"
        )
        return ast.parse(code, mode="eval").body

    def visit_Constant(self, node: ast.Constant):
        if (
            isinstance(node.value, str)
            and id(node) not in self._docstring_ids
            and self._spec_depth == 0
            and 0 < len(node.value) <= 4096
        ):
            self._used = True
            raw = node.value.encode("utf-8", "surrogatepass")
            scheme = random.choice(
                (
                    self._xor_pos,
                    self._xor_rev,
                    self._xor_split,
                    self._rc4_scheme,
                    self._modadd_scheme,
                )
            )
            return ast.copy_location(scheme(raw), node)
        return node

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
        can_wrap = self._spec_depth == 0 or (
            self._spec_depth == 1
            and not any(isinstance(v, ast.FormattedValue) for v in node.values)
        )
        values = []
        for item in node.values:
            if isinstance(item, ast.Constant) and can_wrap:
                enc = self.visit(item)
                if isinstance(enc, ast.Constant):
                    values.append(enc)
                else:
                    values.append(
                        ast.FormattedValue(
                            value=enc, conversion=-1, format_spec=None
                        )
                    )
            elif isinstance(item, ast.Constant):
                values.append(item)
            else:
                values.append(self.visit(item))
        node.values = values
        return node

    def visit_MatchValue(self, node):
        return node

    def visit_MatchSingleton(self, node):
        return node

    def visit_MatchSequence(self, node):
        return node

    def visit_MatchMapping(self, node):
        return node

    def visit_MatchClass(self, node):
        return node

    def visit_MatchStar(self, node):
        return node

    def visit_MatchAs(self, node):
        return node

    def visit_MatchOr(self, node):
        return node


def _opaque_true() -> ast.expr:
    x = random.randint(2, 9999)
    choice = random.randint(0, 3)
    if choice == 0:
        code = f"(({x} ** 2 + 1) > 0)"
    elif choice == 1:
        code = f"(({x} * 0) == 0)"
    elif choice == 2:
        code = "(hash(None) == hash(None))"
    else:
        code = f"(({x} & 255) <= 255)"
    return ast.parse(code, mode="eval").body


def make_junk_functions(count: int | None = None) -> list[ast.FunctionDef]:
    if count is None:
        count = random.randint(14, 22)
    funcs: list[ast.FunctionDef] = []
    prev_names: list[str] = []
    for _ in range(count):
        fn_name = rand_confuse_name()
        p1 = rand_confuse_name(10)
        p2 = rand_confuse_name(10)
        v1 = rand_confuse_name(10)
        v2 = rand_confuse_name(10)
        k1 = random.randint(1, 0xFFFF)
        k2 = random.randint(1, 0xFFFF)
        if prev_names:
            callee = random.choice(prev_names)
            else_expr = f"{callee}({p1}, {p2})"
        else:
            else_expr = f"({p1} ^ {p2})"
        src = (
            f"def {fn_name}({p1}={k1}, {p2}={k2}):\n"
            f"    {v1} = ({p1} ^ {k2}) + ({p2} & 255)\n"
            f"    if True:\n"
            f"        {v2} = {v1} ^ {k1}\n"
            f"    else:\n"
            f"        {v2} = {else_expr}\n"
            f"    try:\n"
            f"        return ({v2} + {p1}) & 0xFFFFFFFF\n"
            f"    except Exception:\n"
            f"        return {k1}\n"
        )
        fn_node = ast.parse(src).body[0]
        if isinstance(fn_node, ast.FunctionDef):
            for sub in fn_node.body:
                if isinstance(sub, ast.If):
                    sub.test = _opaque_true()
            funcs.append(fn_node)
            prev_names.append(fn_name)
    return funcs


def inject_junk(tree_or_source, count: int | None = None):
    is_str = isinstance(tree_or_source, str)
    if is_str:
        try:
            tree = ast.parse(tree_or_source)
        except SyntaxError:
            return tree_or_source
    else:
        tree = tree_or_source
    start = _safe_insert_index(tree)
    for fn in make_junk_functions(count):
        pos = random.randint(start, max(start, len(tree.body)))
        tree.body.insert(pos, fn)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) if is_str else tree


def _has_flow_break(stmt: ast.AST) -> bool:
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if isinstance(
        stmt,
        (
            ast.Return,
            ast.Yield,
            ast.YieldFrom,
            ast.Break,
            ast.Continue,
            ast.Global,
            ast.Nonlocal,
        ),
    ):
        return True
    if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
        return True
    return any(_has_flow_break(child) for child in ast.iter_child_nodes(stmt))


def flatten_control_flow(tree_or_source):
    is_str = isinstance(tree_or_source, str)
    if is_str:
        try:
            tree = ast.parse(tree_or_source)
        except SyntaxError:
            return tree_or_source
    else:
        tree = tree_or_source

    split_idx = _safe_insert_index(tree)
    prefix = tree.body[:split_idx]
    remaining = tree.body[split_idx:]

    if len(remaining) < 3 or any(_has_flow_break(s) for s in remaining):
        return ast.unparse(tree) if is_str else tree

    if len(remaining) > 24:
        chunk_sz = (len(remaining) + 23) // 24
        blocks = [
            remaining[i : i + chunk_sz] for i in range(0, len(remaining), chunk_sz)
        ]
    else:
        blocks = [[s] for s in remaining]

    n = len(blocks)
    sv = rand_confuse_name()
    shuf_pos = list(range(n))
    random.shuffle(shuf_pos)

    case_order = list(range(n))
    random.shuffle(case_order)

    if_chain: ast.If | None = ast.If(
        test=ast.Compare(
            left=ast.Name(id=sv, ctx=ast.Load()),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=-1)],
        ),
        body=[ast.Break()],
        orelse=[],
    )

    for orig_idx in reversed(case_order):
        next_state = shuf_pos[orig_idx + 1] if orig_idx + 1 < n else -1
        step_body = [
            *blocks[orig_idx],
            ast.Assign(
                targets=[ast.Name(id=sv, ctx=ast.Store())],
                value=ast.Constant(value=next_state),
            ),
        ]
        if_chain = ast.If(
            test=ast.Compare(
                left=ast.Name(id=sv, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=shuf_pos[orig_idx])],
            ),
            body=step_body,
            orelse=[if_chain] if if_chain is not None else [],
        )

    init_assign = ast.Assign(
        targets=[ast.Name(id=sv, ctx=ast.Store())],
        value=ast.Constant(value=shuf_pos[0]),
    )
    loop_node = ast.While(
        test=ast.Constant(value=True),
        body=[if_chain] if if_chain is not None else [ast.Break()],
        orelse=[],
    )

    tree.body = [*prefix, init_assign, loop_node]
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) if is_str else tree
