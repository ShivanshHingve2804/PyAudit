import pytest
from pyaudit.rules.bug_detector import check
from pyaudit.models import Severity, Category

# PA-B001 Mutable Default Argument
def test_mutable_default_list(parse_code):
    tree = parse_code("def foo(x=[]): pass")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B001" for i in issues)

def test_no_mutable_default(parse_code):
    tree = parse_code("def foo(x=None): pass")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B001" for i in issues)

# PA-B002 Bare Except
def test_bare_except(parse_code):
    tree = parse_code("try:\n  pass\nexcept:\n  pass")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B002" for i in issues)

def test_specific_except(parse_code):
    tree = parse_code("try:\n  pass\nexcept Exception:\n  pass")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B002" for i in issues)

# PA-B003 Compare to None using == or !=
def test_compare_to_none_eq(parse_code):
    tree = parse_code("x == None")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B003" for i in issues)

def test_compare_to_none_is(parse_code):
    tree = parse_code("x is None")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B003" for i in issues)

# PA-B004 Assert in Production Code
def test_assert_used(parse_code):
    tree = parse_code("assert x == 1")
    issues = check(tree, "main.py")
    assert any(i.rule_id == "PA-B004" for i in issues)

def test_assert_used_in_test_file(parse_code):
    tree = parse_code("assert x == 1")
    issues = check(tree, "test_main.py")
    assert not any(i.rule_id == "PA-B004" for i in issues)

# PA-B005 Unused Variables
def test_unused_variable(parse_code):
    tree = parse_code("def foo():\n  x = 1\n  return 2")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B005" for i in issues)

def test_used_variable(parse_code):
    tree = parse_code("def foo():\n  x = 1\n  return x")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B005" for i in issues)

# PA-B006 Return with value in __init__
def test_return_in_init(parse_code):
    tree = parse_code("class A:\n  def __init__(self):\n    return 1")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B006" for i in issues)

def test_no_return_in_init(parse_code):
    tree = parse_code("class A:\n  def __init__(self):\n    return")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B006" for i in issues)

# PA-B007 Redefining built-in names
def test_redefining_builtin(parse_code):
    tree = parse_code("list = []")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B007" for i in issues)

def test_not_redefining_builtin(parse_code):
    tree = parse_code("my_list = []")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B007" for i in issues)
