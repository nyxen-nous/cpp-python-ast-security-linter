"""Shared security/identifier patterns used by Python and C++ rules."""

import re

SECRET_NAME = re.compile(
    r"(pass(wd|word)?|pwd|(^|_)pw($|_)|secret|token|api[_]?key"
    r"|auth(?!or)|authoriz(ation|ed)|credential|priv(ate)?[_]?key)", re.I,
)

# Credential words used as metadata qualifiers, not the credential itself.
SECRET_QUALIFIER = re.compile(
    r"(_|^)(type|types|kind|kinds|name|names|field|fields|class|classes|header"
    r"|headers|hdr|hdrs|pattern|patterns|error|errors|scheme|schemes|method"
    r"|methods|list|map|regex|prefix|suffix|label|labels|id|ids|url|uri|endpoint"
    r"|param|params|arg|args|key_name|column|table|attr|attribute|format|template"
    r"|msg|message|text|doc|docs|help|hint|placeholder|example|examples)$", re.I,
)

SNAKE = re.compile(r"^_{0,2}[a-z][a-z0-9_]*_{0,2}$")
PASCAL = re.compile(r"^_?[A-Z][A-Za-z0-9]*$")
