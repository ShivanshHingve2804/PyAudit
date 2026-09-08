# 🔍 PyAudit

<p align="center">
  <strong>Production-grade, zero-dependency Python static code quality and security analyzer powered by native AST inspection.</strong>
</p>

<p align="center">
  <a href="https://github.com/ShivanshHingve2804/PyAudit/actions/workflows/ci.yml"><img src="https://github.com/ShivanshHingve2804/PyAudit/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python Version" />
  <img src="https://img.shields.io/badge/dependencies-0%20external-brightgreen.svg" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code Style: Black" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" />
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#key-features">Key Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start--usage">Quick Start</a> •
  <a href="#example-output">Example Output</a> •
  <a href="#rules-reference">Rules Reference</a> •
  <a href="#project-structure">Project Structure</a> •
  <a href="#docker-usage">Docker</a> •
  <a href="#running-tests">Testing</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

## 📌 Overview

**PyAudit** is a lightweight, high-performance static analysis tool designed to inspect Python codebases for critical bugs, security vulnerabilities, and maintainability anti-patterns.

Unlike conventional linters that pull in heavyweight dependency trees, PyAudit runs **entirely on Python's native standard library** (`ast`, `argparse`, `json`, `dataclasses`, `pathlib`). By traversing Python's Abstract Syntax Tree (AST), PyAudit delivers deterministic, blazing-fast audits without runtime execution overhead or external supply-chain vulnerabilities.

Ideal for local development, pre-commit hooks, containerized workflows, and automated CI/CD pipelines.

---

## ⚡ Key Features

- 🐛 **Bug Detection**
  - Flags mutable default arguments (`def func(x=[])`)
  - Identifies dangerous bare `except:` clauses
  - Enforces `is None` / `is not None` identity comparisons over equality operators (`==`, `!=`)
  - Detects unsafe production `assert` statements that can be bypassed with `-O` flags
  - Catches unused local variables, illegal return values in `__init__`, and accidental built-in shadowing

- 🔒 **Security Scanning**
  - Detects dynamic code execution via `eval()` and `exec()`
  - Scans for hardcoded credentials, API keys, and plain-text passwords
  - Identifies shell command injection vulnerabilities through `os.system()`
  - Flags unsafe deserialization risks with `pickle.loads()`
  - Highlights cryptographically broken hashing functions (MD5, SHA1)
  - Catches dangerous SQL string interpolations susceptible to SQL injection (SQLi)

- 🎨 **Style & Code Smells**
  - Flags excessively long functions (>50 statements)
  - Identifies bloated parameter signatures (>5 arguments)
  - Enforces documentation integrity by identifying missing module, class, and function docstrings
  - Flags functions with high return complexity
  - Detects deeply nested control flow blocks (>4 levels)
  - Warns against namespace pollution from wildcard / star imports (`from module import *`)

- 🚀 **Zero Dependencies**
  - Requires pure Python 3.9+. No external runtime wheels or packages required. Instant cold start and zero supply-chain attack surface.

- 📊 **Flexible Reporting**
  - **Colorized Table**: Visual, formatted output with exact line and column coordinates for developer terminal sessions.
  - **JSON Format**: Machine-parseable schema tailored for CI/CD integrations, SARIF converters, and metric dashboards.
  - **Summary Mode**: Concise issue counters aggregated by severity tier.

- 🐳 **Docker Support**
  - Multi-stage minimal container ready for zero-install pipeline execution.

- ✅ **CI/CD Ready**
  - Automated GitHub Actions workflow included for static checks and automated test runs.

---

## 📦 Installation

### From Source

```bash
# Clone repository
git clone https://github.com/ShivanshHingve2804/PyAudit.git
cd PyAudit

# Install package into current environment
pip install .
```

### Development Installation

To install in editable mode with development and testing dependencies:

```bash
pip install -e ".[dev]"
```

---

## 🚀 Quick Start / Usage

PyAudit provides a clean, UNIX-philosophy CLI interface:

```bash
# Scan a single Python file
pyaudit scan script.py

# Scan an entire project directory recursively
pyaudit scan src/

# Export results in structured JSON format
pyaudit scan src/ --format json

# Filter findings by severity (e.g., HIGH only)
pyaudit scan src/ --severity high

# Filter findings by category (bug, security, style)
pyaudit scan src/ --category security

# Display high-level summary only
pyaudit scan src/ --format summary
```

### Command-Line Arguments Reference

```text
usage: pyaudit scan [-h] [-f {table,json,summary}] [-s {low,medium,high}]
                    [-c {bug,security,style}] [--ignore RULES]
                    targets [targets ...]

positional arguments:
  targets               Files or directories to analyze

options:
  -h, --help            Show this help message and exit
  -f, --format FORMAT   Output format: table, json, summary (default: table)
  -s, --severity LEVEL  Minimum severity threshold: low, medium, high (default: low)
  -c, --category CAT    Filter by category: bug, security, style
  --ignore RULES        Comma-separated list of rule IDs to skip (e.g. PA-C003,PA-B004)
```

---

## 🖥️ Example Output

When auditing target code with issues:

```text
$ pyaudit scan examples/vulnerable.py

📁 examples/vulnerable.py
──────────────────────────────────────────────────────────────────
  Line  │ Col │ Severity │ Rule    │ Message
  ------│-----│----------│---------│---------------------------------
     3  │  0  │ HIGH     │ PA-S001 │ Use of eval() is a security risk
     7  │  4  │ HIGH     │ PA-S003 │ Hardcoded secret: 'password'
    12  │  0  │ MEDIUM   │ PA-B001 │ Mutable default argument: list
    15  │  0  │ LOW      │ PA-C003 │ Missing docstring in function 'process'
──────────────────────────────────────────────────────────────────

📊 Summary: 4 issues found (2 high, 1 medium, 1 low)
```

---

## 📋 Rules Reference

PyAudit ships with **20 built-in rules** categorized under Bug Detection (`PA-B*`), Security Scanning (`PA-S*`), and Code Style (`PA-C*`):

| Rule ID | Category | Severity | Description |
|:-------:|:--------:|:--------:|:------------|
| **PA-B001** | Bug | `Medium` | Mutable default argument detected in function signature (`list`, `dict`, `set`) |
| **PA-B002** | Bug | `Medium` | Bare `except:` clause caught without specifying an exception class |
| **PA-B003** | Bug | `Low` | Comparison to `None` using equality operators (`==` or `!=`) instead of `is` / `is not` |
| **PA-B004** | Bug | `Low` | Use of `assert` statement in production logic (bypassed with `-O` flag) |
| **PA-B005** | Bug | `Medium` | Unused local variable definition detected |
| **PA-B006** | Bug | `Medium` | Explicit value returned in `__init__` constructor method |
| **PA-B007** | Bug | `Medium` | Redefinition or shadowing of a built-in Python name (e.g., `id`, `list`, `type`) |
| **PA-S001** | Security | `High` | Dangerous execution of arbitrary code via `eval()` |
| **PA-S002** | Security | `High` | Dangerous execution of dynamic Python statements via `exec()` |
| **PA-S003** | Security | `High` | Hardcoded password, token, or secret detected in source |
| **PA-S004** | Security | `High` | Unsafe invocation of system shell via `os.system()` |
| **PA-S005** | Security | `High` | Unsafe object deserialization through `pickle.loads()` |
| **PA-S006** | Security | `Medium` | Insecure cryptographic hashing algorithm (MD5 or SHA1) |
| **PA-S007** | Security | `High` | Potential SQL injection via dynamic string formatting in query |
| **PA-C001** | Style | `Low` | Function exceeds statement threshold (>50 statements) |
| **PA-C002** | Style | `Low` | Function definition contains excessive parameters (>5 arguments) |
| **PA-C003** | Style | `Low` | Missing docstring in module, public class, or public function |
| **PA-C004** | Style | `Low` | Function contains excessive `return` statements |
| **PA-C005** | Style | `Medium` | Code block exceeds allowable nesting depth (>4 levels) |
| **PA-C006** | Style | `Low` | Wildcard / star import detected (`from ... import *`) |

---

## 🐳 Docker Usage

PyAudit can be built and run as a self-contained container without needing a local Python environment:

```bash
# Build the Docker image
docker build -t pyaudit .

# Run scan on current workspace directory
docker run --rm -v $(pwd):/code pyaudit scan /code
```

---

## 🧪 Running Tests

PyAudit maintains a comprehensive test suite covering all AST visitors, parsers, and reporters:

```bash
# Run full test suite with verbose output
pytest -v

# Run tests with terminal coverage reporting
pytest --cov=pyaudit --cov-report=term-missing
```

---

## 📁 Project Structure

```text
pyaudit/
├── src/
│   └── pyaudit/
│       ├── __init__.py
│       ├── cli.py
│       ├── analyzer.py
│       ├── models.py
│       ├── reporter.py
│       ├── utils.py
│       └── rules/
│           ├── __init__.py
│           ├── bug_detector.py
│           ├── security_scanner.py
│           └── style_checker.py
├── tests/
│   ├── conftest.py
│   ├── test_analyzer.py
│   ├── test_bug_detector.py
│   ├── test_security_scanner.py
│   ├── test_style_checker.py
│   ├── test_reporter.py
│   └── test_cli.py
├── .github/workflows/ci.yml
├── Dockerfile
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## 🛠️ Architecture & Design Principles

1. **Pure AST Visiting**: PyAudit uses Python's `ast.NodeVisitor` to construct an in-memory abstract syntax tree, analyzing syntactic structures without executing untrusted code.
2. **Deterministic Rules Isolation**: Every rule set (`bug_detector`, `security_scanner`, `style_checker`) is modular and independent, returning strongly-typed issue models.
3. **Zero External Dependencies**: Engineered purely using Python standard library primitives to guarantee that PyAudit can run in any environment where Python 3.9+ is installed.
4. **CI-Friendly Exit Codes**: Automatically returns non-zero status codes upon encountering issues that match or exceed user-configured severity criteria, integrating seamlessly into CI checks and git hooks.

---

## 🤝 Contributing

Contributions are welcomed! Follow these standard steps:

1. **Fork the Repository**: Click "Fork" at the top right of the GitHub repository.
2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/awesome-new-rule
   ```
3. **Make Your Changes**: Write clean, well-documented code adhering to PEP 8 standards. Add corresponding test cases in `tests/`.
4. **Run Verification**:
   ```bash
   pytest -v
   ```
5. **Commit Your Changes**:
   ```bash
   git commit -m "feat(rules): add PA-X001 rule for detection"
   ```
6. **Push to Your Fork & Open a Pull Request**:
   ```bash
   git push origin feature/awesome-new-rule
   ```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Shivansh Hingve**
- GitHub: [@ShivanshHingve2804](https://github.com/ShivanshHingve2804)
