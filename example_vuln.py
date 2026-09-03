"""
Vulnerable-code corpus (Python).

Each function contains one deliberate weakness. The EXPECT comment above
each names the rule that must fire, so this file doubles as the expected
results record used by  python run.py --selftest.
"""

import hashlib
import os
import pickle
import subprocess

import yaml

# EXPECT PY.SEC.003
api_key = "sk-live-9f8a7b6c5d4e3f2a1b0c"


def run_user_command(user_input):
    # EXPECT PY.SEC.002
    subprocess.run(user_input, shell=True)


def calculate(expression):
    # EXPECT PY.SEC.001
    return eval(expression)


def loadData(raw_bytes):
    # EXPECT PY.SEC.004
    # EXPECT PY.STYLE.001
    return pickle.loads(raw_bytes)


def cleanup(path):
    # EXPECT PY.SEC.005
    os.system("rm -rf " + path)


def weak_hash(password):
    # EXPECT PY.SEC.006
    return hashlib.md5(password.encode()).hexdigest()


def load_config(text):
    # EXPECT PY.SEC.007
    return yaml.load(text)


def find_user(cursor, name):
    # EXPECT PY.SEC.008
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")


def fetch_insecure(url):
    import requests
    # EXPECT PY.SEC.009
    return requests.get(url, verify=False)


def guard(user):
    # EXPECT PY.SEC.010
    assert user.is_admin, "admin required"


def start():
    from flask import Flask
    app = Flask(__name__)
    # EXPECT PY.SEC.011
    app.run(debug=True)


def add_items(item, bucket=[]):
    # EXPECT PY.QUAL.002
    bucket.append(item)
    return bucket


def divide(a, b):
    try:
        return a / b
    except:
        # EXPECT PY.QUAL.001
        return None


def check(value):
    # EXPECT PY.QUAL.004
    if value == None:
        return "empty"
    return "set"
