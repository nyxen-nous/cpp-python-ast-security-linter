"""Near-miss corpus for PY.SEC.003.

Every name below contains a credential word, but as a *qualifier* describing
metadata rather than as a credential. These are the exact shapes that made the
analyzer report 35 false positives against the Python standard library's
`email` package, where `token_type = 'unstructured'` appears dozens of times.

Nothing in this file may produce a finding.
"""

token_type = "unstructured"
token_kind = "encoded-word"
auth_scheme = "bearer-authentication"
password_field = "user_password_input"
credential_id = "abc123def456"
secret_name = "database-primary"
api_key_label = "Production API Key"
token_pattern = "^[a-z0-9]{32}$"
authorization_header = "X-Custom-Authorization"
token_list = "alpha,beta,gamma"
secret_url = "https://vault.example.internal"
password_prefix = "user_account_"
auth_error = "invalid_grant_supplied"
token_format = "compact-serialization"


class Parser:
    """Attribute assignment goes through the same rule path."""

    def __init__(self):
        self.token_type = "bare-quoted-string"
        self.auth_method = "digest-authentication"
