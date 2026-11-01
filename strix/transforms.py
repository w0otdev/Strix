# Copyright (c) 2026 w0otdev (Strix modifications)
# Original work Copyright (c) ktn1703 (https://github.com/ktn1703/Neo)
# Licensed under the Apache License, Version 2.0.
# Modified by w0otdev: Modularized and rebranded under Strix.

import ast
import random

from .context import BUILTINS, HIDE_LIST, I_, QN, B, F, I, S, hz


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
        body = t.body
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
                        ast.Expr(
                            ast.Call(
                                func=ast.Name(id="exit", ctx=ast.Load()),
                                args=[],
                                keywords=[],
                            )
                        ),
                    ],
                ),
                ast.ExceptHandler(
                    type=ast.Name(id="Exception", ctx=ast.Load()),
                    name="e",
                    body=[
                        ast.Expr(
                            ast.Call(
                                func=ast.Name(id="print", ctx=ast.Load()),
                                args=[ast.Name(id="e", ctx=ast.Load())],
                                keywords=[],
                            )
                        )
                    ],
                ),
            ],
            orelse=[],
            finalbody=[],
        )
        m = ast.Module(body=[try_except], type_ignores=[])
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
                vl.append(str(i.value))
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


def obf_vars(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(n.name == "*" for n in node.names):
            return source

    module_names = set()
    declared = set()
    method_names = set()
    attr_names = set()
    kwarg_names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            module_names.add(node.names[0].name.split(".")[0])
            if node.names[0].asname:
                declared.add(node.names[0].asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module_names.add(node.module.split(".")[0])
            for a in node.names:
                if a.asname:
                    declared.add(a.asname)
                else:
                    module_names.add(a.name)
        elif isinstance(node, ast.Attribute):
            attr_names.add(node.attr)
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg:
                    kwarg_names.add(kw.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            declared.add(node.name)
        elif isinstance(node, ast.arg):
            declared.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            declared.add(node.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            declared.update(node.names)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                declared.add(node.name)

    for parent in ast.walk(tree):
        if isinstance(parent, ast.ClassDef):
            for sub in parent.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_names.add(sub.name)

    not_rename = attr_names | kwarg_names | method_names
    aliases = {}
    for name in declared:
        if name in aliases or name in module_names or name in BUILTINS:
            continue
        if name.startswith("__") or name in ("self", "cls", "_"):
            continue
        if name in not_rename:
            continue
        aliases[name] = hz()

    class Ren(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in aliases:
                node.id = aliases[node.id]
            return node

        def visit_FunctionDef(self, node):
            if node.name in aliases:
                node.name = aliases[node.name]
            self.generic_visit(node)
            return node

        def visit_AsyncFunctionDef(self, node):
            if node.name in aliases:
                node.name = aliases[node.name]
            self.generic_visit(node)
            return node

        def visit_ClassDef(self, node):
            if node.name in aliases:
                node.name = aliases[node.name]
            self.generic_visit(node)
            return node

        def visit_arg(self, node):
            if node.arg in aliases:
                node.arg = aliases[node.arg]
            return node

        def visit_Global(self, node):
            node.names = [aliases.get(x, x) for x in node.names]
            return node

        def visit_Nonlocal(self, node):
            node.names = [aliases.get(x, x) for x in node.names]
            return node

    tree = Ren().visit(tree)
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


def gen_jcode(code):
    men = hz()
    bao = hz()
    qua = hz()
    return [
        ast.Assign(
            targets=[ast.Name(id=bao, ctx=ast.Store())], value=ast.Constant(value=men)
        ),
        ast.Assign(
            targets=[ast.Name(id=qua, ctx=ast.Store())], value=ast.Constant(value=True)
        ),
        ast.If(
            test=ast.BoolOp(
                op=ast.And(),
                values=[
                    ast.Compare(
                        left=ast.Name(id=bao, ctx=ast.Load()),
                        ops=[ast.Eq()],
                        comparators=[ast.Constant(value=men)],
                    ),
                    ast.Compare(
                        left=ast.Name(id=qua, ctx=ast.Load()),
                        ops=[ast.NotEq()],
                        comparators=[ast.Constant(value=True)],
                    ),
                ],
            ),
            body=[
                ast.Expr(
                    value=ast.Lambda(
                        args=ast.arguments(
                            posonlyargs=[],
                            args=[],
                            kwonlyargs=[],
                            kw_defaults=[],
                            defaults=[],
                        ),
                        body=ast.parse(S("灵魂暗影"), mode="eval").body,
                    )
                )
            ],
            orelse=[
                ast.If(
                    test=ast.BoolOp(
                        op=ast.And(),
                        values=[
                            ast.Compare(
                                left=ast.Name(id=bao, ctx=ast.Load()),
                                ops=[ast.Eq()],
                                comparators=[ast.Constant(value=men)],
                            ),
                            ast.Compare(
                                left=ast.Name(id=qua, ctx=ast.Load()),
                                ops=[ast.NotEq()],
                                comparators=[ast.Constant(value=False)],
                            ),
                        ],
                    ),
                    body=[
                        ast.Try(
                            body=[
                                ast.Expr(
                                    value=ast.Tuple(
                                        elts=[
                                            ast.BinOp(
                                                left=ast.Constant(value=1),
                                                op=ast.Div(),
                                                right=ast.Constant(value=0),
                                            ),
                                            ast.BinOp(
                                                left=ast.Constant(value=123),
                                                op=ast.Div(),
                                                right=ast.Constant(value=0),
                                            ),
                                            ast.BinOp(
                                                left=ast.Constant(value=12312321312),
                                                op=ast.Div(),
                                                right=ast.Constant(value=0),
                                            ),
                                        ],
                                        ctx=ast.Load(),
                                    )
                                )
                            ],
                            handlers=[ast.ExceptHandler(body=[code])],
                            orelse=[],
                            finalbody=[],
                        )
                    ],
                    orelse=[
                        ast.If(
                            test=ast.BoolOp(
                                op=ast.Or(),
                                values=[
                                    ast.Compare(
                                        left=ast.Name(id=bao, ctx=ast.Load()),
                                        ops=[ast.Eq()],
                                        comparators=[
                                            ast.parse(S("废墟"), mode="eval").body
                                        ],
                                    ),
                                    ast.Compare(
                                        left=ast.Name(id=qua, ctx=ast.Load()),
                                        ops=[ast.Eq()],
                                        comparators=[ast.Constant(value=False)],
                                    ),
                                ],
                            ),
                            body=[
                                ast.Expr(
                                    value=ast.Call(
                                        func=ast.Lambda(
                                            args=ast.arguments(
                                                posonlyargs=[],
                                                args=[],
                                                kwonlyargs=[],
                                                kw_defaults=[],
                                                defaults=[],
                                            ),
                                            body=ast.Call(
                                                func=ast.Name(
                                                    id="print", ctx=ast.Load()
                                                ),
                                                args=[
                                                    ast.parse(
                                                        S("虚空回响"), mode="eval"
                                                    ).body
                                                ],
                                                keywords=[],
                                            ),
                                        ),
                                        args=[],
                                        keywords=[],
                                    )
                                )
                            ],
                            orelse=[
                                ast.While(
                                    test=ast.Constant(value=True),
                                    body=[ast.Pass()],
                                    orelse=[],
                                ),
                                ast.Expr(
                                    value=ast.Call(
                                        func=ast.Name(id="print", ctx=ast.Load()),
                                        args=[
                                            ast.parse(S("数字洪流"), mode="eval").body
                                        ],
                                        keywords=[],
                                    )
                                ),
                            ],
                        )
                    ],
                )
            ],
        ),
    ]


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
    for i in olb:
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
    tb[1].handlers[0].body.extend(junk_cases(en, len(olb) + 1))
    node.body = [
        *docstring,
        ast.Assign(
            targets=[ast.Name(id=var, ctx=ast.Store())],
            value=ast.parse(I_(0), mode="eval").body,
        ),
        *tb,
    ]
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
            inner = []
            for index, m in enumerate(node.body):
                if (
                    index == 0
                    and isinstance(m, ast.Expr)
                    and isinstance(m.value, ast.Constant)
                    and isinstance(m.value.value, str)
                ):
                    inner.append(m)
                    continue
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    inner.append(_bl(m))
                elif isinstance(
                    m, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr)
                ):
                    inner.extend(bl([m]))
                else:
                    inner.append(m)
            node.body = inner
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
