"""Tests for the security scanner rules."""

import ast
from pyaudit.rules.security_scanner import check
from pyaudit.models import Severity, Category


def _check_code(code: str) -> list:
    tree = ast.parse(code)
    return check(tree, "test.py")


# PA-S001: eval()
def test_eval_detected():
    issues = _check_code("result = eval(user_input)")
    assert any(i.rule_id == "PA-S001" for i in issues)

def test_no_eval():
    issues = _check_code("result = int('42')")
    assert not any(i.rule_id == "PA-S001" for i in issues)


# PA-S002: exec()
def test_exec_detected():
    issues = _check_code("exec(code_string)")
    assert any(i.rule_id == "PA-S002" for i in issues)

def test_no_exec():
    issues = _check_code("print('hello')")
    assert not any(i.rule_id == "PA-S002" for i in issues)


# PA-S003: Hardcoded secrets
def test_hardcoded_password():
    issues = _check_code('password = "supersecret123"')
    assert any(i.rule_id == "PA-S003" for i in issues)

def test_hardcoded_api_key():
    issues = _check_code('api_key = "sk-abc123def456"')
    assert any(i.rule_id == "PA-S003" for i in issues)

def test_password_from_env_no_flag():
    issues = _check_code('password = os.environ.get("PASSWORD")')
    assert not any(i.rule_id == "PA-S003" for i in issues)

def test_normal_string_var():
    issues = _check_code('name = "hello"')
    assert not any(i.rule_id == "PA-S003" for i in issues)


# PA-S004: os.system()
def test_os_system_detected():
    issues = _check_code('import os\nos.system("rm -rf /")')
    assert any(i.rule_id == "PA-S004" for i in issues)

def test_subprocess_no_flag():
    issues = _check_code('import subprocess\nsubprocess.run(["ls"])')
    assert not any(i.rule_id == "PA-S004" for i in issues)


# PA-S005: pickle.loads()
def test_pickle_loads_detected():
    issues = _check_code('import pickle\npickle.loads(data)')
    assert any(i.rule_id == "PA-S005" for i in issues)

def test_json_loads_no_flag():
    issues = _check_code('import json\njson.loads(data)')
    assert not any(i.rule_id == "PA-S005" for i in issues)


# PA-S006: Weak hashing
def test_md5_detected():
    issues = _check_code('import hashlib\nhashlib.md5(data)')
    assert any(i.rule_id == "PA-S006" for i in issues)

def test_sha256_no_flag():
    issues = _check_code('import hashlib\nhashlib.sha256(data)')
    assert not any(i.rule_id == "PA-S006" for i in issues)


# PA-S007: SQL injection via f-strings
def test_sql_fstring_detected():
    issues = _check_code('query = f"SELECT * FROM users WHERE id = {user_id}"')
    assert any(i.rule_id == "PA-S007" for i in issues)

def test_normal_fstring_no_flag():
    issues = _check_code('msg = f"Hello {name}"')
    assert not any(i.rule_id == "PA-S007" for i in issues)
