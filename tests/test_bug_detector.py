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

# PA-B002 Assert in Production Code
def test_assert_used(parse_code):
    tree = parse_code("assert x == 1")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B002" for i in issues)

def test_no_assert(parse_code):
    tree = parse_code("if not x == 1: raise AssertionError()")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B002" for i in issues)

# PA-B003 Bare Except
def test_bare_except(parse_code):
    tree = parse_code("try:\n  pass\nexcept:\n  pass")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B003" for i in issues)

def test_specific_except(parse_code):
    tree = parse_code("try:\n  pass\nexcept Exception:\n  pass")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B003" for i in issues)

# PA-B004 Pass inside except
def test_pass_in_except(parse_code):
    tree = parse_code("try:\n  pass\nexcept Exception:\n  pass")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B004" for i in issues)

def test_no_pass_in_except(parse_code):
    tree = parse_code("try:\n  pass\nexcept Exception:\n  print('error')")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B004" for i in issues)

# PA-B005 Return inside Finally
def test_return_in_finally(parse_code):
    tree = parse_code("try:\n  pass\nfinally:\n  return 1")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B005" for i in issues)

def test_no_return_in_finally(parse_code):
    tree = parse_code("try:\n  pass\nfinally:\n  pass")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B005" for i in issues)

# PA-B006 Continue inside Finally
def test_continue_in_finally(parse_code):
    tree = parse_code("for i in range(1):\n  try:\n    pass\n  finally:\n    continue")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B006" for i in issues)

def test_no_continue_in_finally(parse_code):
    tree = parse_code("for i in range(1):\n  try:\n    pass\n  finally:\n    pass")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B006" for i in issues)

# PA-B007 Duplicate Dictionary Keys
def test_duplicate_dict_keys(parse_code):
    tree = parse_code("d = {'a': 1, 'a': 2}")
    issues = check(tree, "test.py")
    assert any(i.rule_id == "PA-B007" for i in issues)

def test_no_duplicate_dict_keys(parse_code):
    tree = parse_code("d = {'a': 1, 'b': 2}")
    issues = check(tree, "test.py")
    assert not any(i.rule_id == "PA-B007" for i in issues)
