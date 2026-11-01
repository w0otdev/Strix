import ast
import contextlib
import io
import struct
import types
import unittest

from strix.literals import harden_literals


def execute(source):
    namespace = {}
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(compile(source, "<test>", "exec"), namespace)
    return namespace, output.getvalue()


def constants(code):
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            yield from constants(value)
        elif isinstance(value, tuple):
            yield from value
        else:
            yield value


class LiteralTests(unittest.TestCase):
    def test_round_trip_all_types_and_special_floats(self):
        source = (
            "values = ('Tiếng Việt 🦉', '\\ud800', '', "
            "b'\\x00\\xff\\x80', b'', True, False, None, Ellipsis, "
            "0, -123, 2**200, 0.0, -0.0, 3.141592653589793, 1e1000, 3j)"
        )
        original, _ = execute(source)
        for fragment in (False, True):
            with self.subTest(fragment=fragment):
                result, _ = execute(harden_literals(source, fragment=fragment))
                self.assertEqual(result["values"], original["values"])
                for index in (12, 13):
                    self.assertEqual(
                        struct.pack(">d", result["values"][index]),
                        struct.pack(">d", original["values"][index]),
                    )

    def test_repeated_literals_have_distinct_ciphertext_and_nonces(self):
        tree = ast.parse(harden_literals("values = ('repeat secret', 'repeat secret')"))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and len(node.args) == 4
            and isinstance(node.args[0], ast.Tuple)
        ]
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(ast.dump(calls[0].args[0]), ast.dump(calls[1].args[0]))
        self.assertNotEqual(ast.dump(calls[0].args[2]), ast.dump(calls[1].args[2]))

    def test_plaintext_does_not_survive_in_compiled_constants(self):
        secret = "private literal with enough length to be recognizable"
        blob = b"\x00\xffbinary literal hidden from co_consts"
        number = 912345678901234567890123456789
        hardened = harden_literals(f"values = ({secret!r}, {blob!r}, {number})")
        values = list(constants(compile(hardened, "<test>", "exec")))
        self.assertNotIn(secret, values)
        self.assertNotIn(blob, values)
        self.assertNotIn(number, values)
        result, _ = execute(hardened)
        self.assertEqual(result["values"], (secret, blob, number))

    def test_fragmented_literal_reconstructs_arbitrary_binary(self):
        blob = bytes(range(256)) * 4
        hardened = harden_literals(f"value = {blob!r}", fragment=True)
        tree = ast.parse(hardened)
        call = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and len(node.args) == 4
            and isinstance(node.args[0], ast.Tuple)
        )
        parts = call.args[0]
        assert isinstance(parts, ast.Tuple)
        self.assertGreater(len(parts.elts), 20)
        result, _ = execute(hardened)
        self.assertEqual(result["value"], blob)

    def test_large_literal_does_not_exceed_integer_literal_limits(self):
        blob = bytes(range(256)) * 80
        result, _ = execute(harden_literals(f"value = {blob!r}"))
        self.assertEqual(result["value"], blob)

    def test_each_build_has_a_distinct_encoding_with_identical_behavior(self):
        source = "print('same behavior', 123456789)"
        first = harden_literals(source, fragment=True)
        second = harden_literals(source, fragment=True)
        self.assertNotEqual(first, second)
        self.assertEqual(execute(first)[1], execute(source)[1])
        self.assertEqual(execute(second)[1], execute(source)[1])

    def test_fstrings_patterns_and_side_effect_order(self):
        source = (
            "events = []\n"
            "def value(x):\n    events.append(x)\n    return x\n"
            "print(f'{value(1)} {value(2)!r:>{value(3)}}')\n"
            "match {'key': 7}:\n"
            "    case {'key': 7}:\n        print('matched')\n"
            "print(events)\n"
        )
        _, expected = execute(source)
        _, actual = execute(harden_literals(source, fragment=True))
        self.assertEqual(actual, expected)

    def test_docstrings_future_imports_and_shadowed_builtins(self):
        source = (
            "'''module docstring'''\n"
            "from __future__ import annotations\n"
            "def fn(x: Unresolved):\n    '''function docstring'''\n    return x\n"
            "bytes = len = range = enumerate = complex = None\n"
            "value = ('text', b'\\xff', 3.5, 2j)\n"
        )
        original, _ = execute(source)
        result, _ = execute(harden_literals(source))
        self.assertEqual(result["value"], original["value"])
        self.assertEqual(result["__doc__"], original["__doc__"])
        self.assertEqual(result["fn"].__doc__, original["fn"].__doc__)
        self.assertEqual(result["fn"].__annotations__, original["fn"].__annotations__)


if __name__ == "__main__":
    unittest.main()
