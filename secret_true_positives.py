"""Counterpart to secret_qualifiers.py.

The qualifier suppression narrows PY.SEC.003. This file proves the narrowing
did not swallow the real detections: every assignment here is a genuine
hard-coded credential and must still be reported.

EXPECT PY.SEC.003
"""

password = "s3cr3t-p4ssw0rd"
api_key = "AKIAIOSFODNN7EXAMPLE"
SECRET_KEY = "django-insecure-8f3d9a2b4c6e"
private_key = "MIIEpAIBAAKCAQEAx7Gk"
auth_token = "ghp_16C7e42F292c6912"
db_password = "postgres-admin-2024"
passwd = "rootrootroot"
