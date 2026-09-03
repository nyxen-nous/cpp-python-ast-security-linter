# Safe counterparts for the additional Python rules.

import hashlib
import logging
import os
import requests
import tarfile
import tempfile

logger = logging.getLogger(__name__)


def fetch_fixed():
    return requests.get("https://example.com", timeout=5)


def create_temp():
    with tempfile.NamedTemporaryFile() as fh:
        return fh.name


def configure():
    os.chmod("private.txt", 0o640)


def safe_archive():
    with tarfile.open("archive.tar") as tar:
        tar.extractall("/tmp/app", filter="data")


def log_event():
    password_prompt = "Please enter your password"
    logger.info("prompt=%s", password_prompt)
    logger.info("authentication succeeded")


def checksum(data):
    return hashlib.sha256(data).hexdigest()
