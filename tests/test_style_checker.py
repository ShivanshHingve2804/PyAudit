"""Tests for the style checker rules."""

import ast
from pyaudit.rules.style_checker import check
from pyaudit.models import Severity, Category


def _check_code(code: str) -> list:
    tree = ast.parse(code)
    return check(tree, "test.py")


# PA-C001: Function too long
def test_long_function():
    lines = ["    x = 1"] * 55
    code = "def long_func():\n" + "\n".join(lines)
    issues = _check_code(code)
    assert any(i.rule_id == "PA-C001" for i in issues)

def test_short_function():
    code = "def short_func():\n    x = 1\n    return x"
    issues = _check_code(code)
    assert not any(i.rule_id == "PA-C001" for i in issues)


# PA-C002: Too many arguments
def test_too_many_args():
    code = "def func(a, b, c, d, e, f, g): pass"
    issues = _check_code(code)
    assert any(i.rule_id == "PA-C002" for i in issues)

def test_ok_args():
    code = "def func(a, b, c): pass"
    issues = _check_code(code)
    assert not any(i.rule_id == "PA-C002" for i in issues)

def test_self_excluded():
    code = "class A:\n    def method(self, a, b, c, d, e): pass"
    issues = _check_code(code)
    assert not any(i.rule_id == "PA-C002" for i in issues)


# PA-C003: Missing docstring
def test_missing_docstring():
    code = "def no_docs():\n    pass"
    issues = _check_code(code)
    assert any(i.rule_id == "PA-C003" for i in issues)

def test_has_docstring():
    code = 'def has_docs():\n    """This has docs."""\n    pass'
    issues = _check_code(code)
    assert not any(i.rule_id == "PA-C003" for i in issues)

def test_private_no_docstring_ok():
    code = "def _private():\n    pass"
    issues = _check_code(code)
    assert not any(i.rule_id == "PA-C003" for i in issues)

def test_class_missing_docstring():
    code = "class MyClass:\n    pass"
    issues = _check_code(code)
    assert any(i.rule_id == "PA-C003" for i in issues)


# PA-C006: Star import
def test_star_import():
    code = "from os import *"
    issues = _check_code(code)
    assert any(i.rule_id == "PA-C006" for i in issues)

def test_normal_import():
    code = "from os import path"
    issues = _check_code(code)
    assert not any(i.rule_id == "PA-C006" for i in issues)
