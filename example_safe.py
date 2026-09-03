"""
Safe-code corpus (Python).

Every function here is the safe counterpart of a pattern the analyzer
detects - deliberate near-misses that a careless rule would flag. The
analyzer must report ZERO findings in this file. This is the false
positive test, and it is the number that actually matters.
"""

import hashlib
import os
import shlex
import subprocess

import yaml


def run_command_safely(directory):
    """Argument list, no shell - the safe form of PY.SEC.002."""
    return subprocess.run(["ls", "-la", directory], shell=False)


def get_api_key():
    """Secret read from the environment - the safe form of PY.SEC.003."""
    return os.environ.get("API_KEY")


password_prompt = "Please enter your password to continue"   # prompt, not a secret


def load_config(text):
    """safe_load cannot construct objects - the safe form of PY.SEC.007."""
    return yaml.safe_load(text)


def hash_password(password):
    """SHA-256 rather than MD5 - the safe form of PY.SEC.006."""
    return hashlib.sha256(password.encode()).hexdigest()


def file_checksum(data):
    """MD5 for a non-security checksum, marked explicitly."""
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def append_item(item, bucket=None):
    """None default - the safe form of PY.QUAL.002."""
    if bucket is None:
        bucket = []
    bucket.append(item)
    return bucket


def parse_number(raw):
    """Specific exception - the safe form of PY.QUAL.001."""
    try:
        return int(raw)
    except ValueError:
        return 0


def check(value):
    """Identity comparison - the safe form of PY.QUAL.004."""
    if value is None:
        return "empty"
    return "set"


def find_user(cursor, name):
    """Parameterised query - the safe form of PY.SEC.008."""
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))


def escape_then_run(user_value):
    """shlex.quote sanitises the value before it reaches a shell."""
    safe = shlex.quote(user_value)
    subprocess.run(["echo", safe], shell=False)


def constant_eval():
    """eval on a literal is reported at LOW, not as a HIGH finding."""
    return 4


def add(a, b):
    return a + b
