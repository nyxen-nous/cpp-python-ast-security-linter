"""
Python rules.

Every rule matches on real AST nodes. Where a rule can be made more precise
by knowing where a value came from, it consults the taint analyzer and
adjusts both its severity and its stated confidence - which is why the same
eval() call can be reported as LOW on a constant and HIGH on user input.
"""

import ast
import re

from ..core.finding import (
    CRITICAL, HIGH, MEDIUM, LOW,
    CONF_HIGH, CONF_MEDIUM, CONF_LOW, Edit,
)
from ..core.rule import Rule, register
from ..core.patterns import SECRET_NAME, SECRET_QUALIFIER, SNAKE, PASCAL

LANG = "python"



def dotted(node):
    parts, cur = [], node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def call_name(node, ctx):
    """Resolved dotted name of a call, seeing through import aliases."""
    raw = dotted(node.func)
    if not raw:
        return ""
    head, _, rest = raw.partition(".")
    real = ctx.resolve(head)
    return f"{real}.{rest}" if rest else real


def is_const(node):
    return isinstance(node, ast.Constant)


def taint_path(node, ctx):
    ta = getattr(ctx, "taint_analyzer", None)
    return ta.path_for_call(node) if ta else None


def args_constant(node, ctx):
    """True when the call's arguments all resolve to compile-time constants."""
    ta = getattr(ctx, "taint_analyzer", None)
    if ta is not None and ta.args_are_constant(node):
        return True
    return bool(node.args) and all(is_const(a) for a in node.args)


def resolve_literal_name(node, ctx, max_depth=4):
    """Resolve a simple variable binding to a literal value when safe to do so."""
    if isinstance(node, ast.Constant):
        return node.value
    if not isinstance(node, ast.Name) or max_depth <= 0:
        return None
    fn = getattr(node, "_usict_fn", None)
    assignment = ctx.assignment_before(node.id, getattr(node, "lineno", 10**9), fn)
    if assignment is None:
        return None
    value = getattr(assignment, "value", None)
    return resolve_literal_name(value, ctx, max_depth - 1)


def _span(node):
    return (node.lineno, node.col_offset,
            getattr(node, "end_lineno", node.lineno),
            getattr(node, "end_col_offset", None))


# ═════════════════════════════════════════════════════════ security rules
@register
class PyDynamicEval(Rule):
    id = "PY.SEC.001"
    language = LANG
    category = "security"
    severity = CRITICAL
    base_confidence = CONF_MEDIUM
    cwe = "CWE-95"
    message = "Dynamic evaluation via eval()/exec()"
    explanation = ("eval() and exec() run their argument as Python code. If any part "
                   "of that string can be influenced by an attacker, they can run "
                   "arbitrary code inside your process.")
    remediation = "Use ast.literal_eval() for data, or an explicit dispatch dict for commands."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        if call_name(node, ctx) not in {"eval", "exec", "compile"}:
            return []
        path = taint_path(node, ctx)
        args = node.args
        if path:
            return [self.make(ctx, node.lineno, node.col_offset,
                              severity=HIGH, confidence=CONF_HIGH,
                              confidence_reason=f"untrusted input traced from line {path[0].line}",
                              taint_path=path)]
        if args_constant(node, ctx):
            f = self.make(ctx, node.lineno, node.col_offset,
                          confidence=CONF_LOW,
                          confidence_reason="argument resolves to a compile-time constant")
            f.severity = LOW
            return [f]
        return [self.make(ctx, node.lineno, node.col_offset,
                          confidence=CONF_MEDIUM,
                          confidence_reason="argument is a variable that could not be traced")]


@register
class PyShellTrue(Rule):
    id = "PY.SEC.002"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-78"
    message = "subprocess call with shell=True"
    explanation = ("shell=True runs the command through a system shell, so any "
                   "attacker-controlled fragment can inject extra commands using "
                   "characters like ; or |.")
    remediation = "Pass the command as a list and leave shell=False (the default)."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        name = call_name(node, ctx)
        if not name.startswith("subprocess."):
            return []
        shell = any(k.arg == "shell" and is_const(k.value) and k.value.value is True
                    for k in node.keywords)
        if not shell:
            return []
        ta = getattr(ctx, "taint_analyzer", None)
        if ta is not None and ta.call_has_sink_sanitizer(node):
            return []
        path = taint_path(node, ctx)
        if path:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_HIGH,
                              confidence_reason=f"untrusted input traced from line {path[0].line}",
                              taint_path=path)]
        return [self.make(ctx, node.lineno, node.col_offset,
                          confidence_reason="shell=True is set; command origin not traced")]


@register
class PyHardcodedSecret(Rule):
    id = "PY.SEC.003"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_MEDIUM
    cwe = "CWE-798"
    message = "Possible hard-coded secret"
    explanation = ("A string literal assigned to a credential-named variable is "
                   "committed to version control, where it stays in the history even "
                   "after it is removed.")
    remediation = "Read secrets from environment variables or a secrets manager."
    PLACEHOLDER = re.compile(r"^(|x{3,}|\.{3,}|<.*>|\{.*\}|none|null|todo|changeme|your[_-].*)$", re.I)
    PROMPTY = re.compile(r"(enter|please|prompt|input|label|message|description|invalid|missing)", re.I)

    def check(self, node, ctx):
        if not isinstance(node, ast.Assign):
            return []
        out = []
        for t in node.targets:
            name = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else "")
            if not name or not SECRET_NAME.search(name):
                continue
            # `token_type = 'unstructured'` names a category, not a credential.
            if SECRET_QUALIFIER.search(name):
                continue
            v = node.value
            if not (is_const(v) and isinstance(v.value, str)):
                continue
            val = v.value
            if len(val) < 8 or self.PLACEHOLDER.match(val):
                continue
            # A sentence with spaces is far more likely a prompt than a key.
            if " " in val.strip() and self.PROMPTY.search(val):
                continue
            conf = CONF_LOW if " " in val else CONF_MEDIUM
            out.append(self.make(
                ctx, node.lineno, node.col_offset,
                message=f"Possible hard-coded secret in '{name}'",
                confidence=conf,
                confidence_reason=("value contains spaces, may be prompt text"
                                   if conf == CONF_LOW else
                                   "credential-style name assigned a literal string"),
            ))
        return out


@register
class PyInsecureDeserialize(Rule):
    id = "PY.SEC.004"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-502"
    message = "Insecure deserialization via pickle"
    explanation = ("Unpickling data lets whoever produced that data execute arbitrary "
                   "code during load - a crafted pickle is a remote code execution "
                   "primitive, not just malformed data.")
    remediation = "Use JSON or another format that cannot construct arbitrary objects."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        if call_name(node, ctx) in {"pickle.load", "pickle.loads",
                                    "cPickle.load", "cPickle.loads",
                                    "dill.load", "dill.loads"}:
            path = taint_path(node, ctx)
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_HIGH if path else CONF_MEDIUM,
                              confidence_reason=(f"untrusted input traced from line {path[0].line}"
                                                 if path else "input source not traced"),
                              taint_path=path or [])]
        return []


@register
class PyOsSystem(Rule):
    id = "PY.SEC.005"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-78"
    message = "os.system() executes a shell command"
    explanation = ("os.system() passes its argument to the shell. Any user-controlled "
                   "fragment can add extra commands.")
    remediation = "Use subprocess.run([...], shell=False) with an argument list."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        if call_name(node, ctx) not in {"os.system", "os.popen"}:
            return []
        path = taint_path(node, ctx)
        if path:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_HIGH,
                              confidence_reason=f"untrusted input traced from line {path[0].line}",
                              taint_path=path)]
        const = args_constant(node, ctx)
        return [self.make(ctx, node.lineno, node.col_offset,
                          confidence=CONF_LOW if const else CONF_MEDIUM,
                          confidence_reason=("command resolves to a constant string" if const
                                             else "command is built at runtime"))]


@register
class PyWeakHash(Rule):
    id = "PY.SEC.006"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_MEDIUM
    cwe = "CWE-327"
    message = "Weak hashing algorithm (MD5/SHA1)"
    explanation = ("MD5 and SHA-1 are broken for security purposes - collisions are "
                   "practical to produce. They remain fine for non-security checksums.")
    remediation = "Use hashlib.sha256(), or bcrypt/argon2 for passwords."
    fixable = True
    CHECKSUMMY = re.compile(r"(checksum|etag|cache|digest_file|dedup|fingerprint|hash_file)", re.I)

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        name = call_name(node, ctx)
        if name not in {"hashlib.md5", "hashlib.sha1"}:
            return []

        # usedforsecurity=False is an explicit, correct opt-out
        for k in node.keywords:
            if k.arg == "usedforsecurity" and is_const(k.value) and k.value.value is False:
                return []

        fn = ctx.function.name if ctx.function is not None else ""
        checksum_ctx = bool(self.CHECKSUMMY.search(fn)) or bool(self.CHECKSUMMY.search(ctx.line_text(node.lineno)))
        algo = name.split(".")[1]

        fix = None
        if not checksum_ctx and isinstance(node.func, ast.Attribute):
            a = node.func
            fix = Edit(
                line=a.value.lineno, col=a.value.col_offset,
                end_line=getattr(a, "end_lineno", a.value.lineno),
                end_col=getattr(a, "end_col_offset", None),
                replacement=f"{dotted(a.value)}.sha256",
                describe=f"replace hashlib.{algo} with hashlib.sha256",
            )

        return [self.make(
            ctx, node.lineno, node.col_offset,
            message=f"Use of weak hash {algo}()",
            confidence=CONF_LOW if checksum_ctx else CONF_MEDIUM,
            confidence_reason=("surrounding names suggest a non-security checksum"
                               if checksum_ctx else "no indication this is a plain checksum"),
            fix=fix,
        )]


@register
class PyYamlLoad(Rule):
    id = "PY.SEC.007"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_HIGH
    cwe = "CWE-502"
    message = "yaml.load() without a safe Loader"
    explanation = ("The default YAML loader can construct arbitrary Python objects, "
                   "which makes loading untrusted YAML equivalent to running it.")
    remediation = "Use yaml.safe_load(), or pass Loader=yaml.SafeLoader."
    fixable = True
    SAFE = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}

    def check(self, node, ctx):
        if not isinstance(node, ast.Call) or call_name(node, ctx) != "yaml.load":
            return []
        for k in node.keywords:
            if k.arg == "Loader":
                if dotted(k.value).split(".")[-1] in self.SAFE:
                    return []
        if len(node.args) >= 2 and dotted(node.args[1]).split(".")[-1] in self.SAFE:
            return []

        fix = None
        if isinstance(node.func, ast.Attribute):
            a = node.func
            fix = Edit(
                line=a.value.lineno, col=a.value.col_offset,
                end_line=getattr(a, "end_lineno", a.value.lineno),
                end_col=getattr(a, "end_col_offset", None),
                replacement=f"{dotted(a.value)}.safe_load",
                describe="replace yaml.load with yaml.safe_load",
            )
        return [self.make(ctx, node.lineno, node.col_offset,
                          confidence_reason="no safe Loader argument present", fix=fix)]


@register
class PySqlInjection(Rule):
    id = "PY.SEC.008"
    language = LANG
    category = "security"
    severity = CRITICAL
    base_confidence = CONF_MEDIUM
    cwe = "CWE-89"
    message = "SQL query built by string construction"
    explanation = ("Building SQL by concatenation or f-string lets input change the "
                   "structure of the query rather than just its values.")
    remediation = "Use parameterised queries: cursor.execute('... WHERE id = ?', (value,))."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        if call_name(node, ctx).split(".")[-1] not in {"execute", "executemany", "executescript"}:
            return []
        if not node.args:
            return []
        q = node.args[0]
        ta = getattr(ctx, "taint_analyzer", None)
        if ta is not None and ta.is_literal_arg(node, 0):
            return []
        built = (isinstance(q, ast.JoinedStr)
                 or (isinstance(q, ast.BinOp) and isinstance(q.op, (ast.Add, ast.Mod)))
                 or (isinstance(q, ast.Call) and dotted(q.func).endswith(".format")))
        ta = getattr(ctx, "taint_analyzer", None)
        if not built and isinstance(q, ast.Name) and ta is not None:
            built = ta.is_dynamic_string_arg(node, 0)
        if not built:
            return []
        path = taint_path(node, ctx)
        return [self.make(ctx, node.lineno, node.col_offset,
                          confidence=CONF_HIGH if path else CONF_MEDIUM,
                          confidence_reason=(f"untrusted input traced from line {path[0].line}"
                                             if path else "query is assembled from a non-literal"),
                          taint_path=path or [])]


@register
class PyRequestsNoVerify(Rule):
    id = "PY.SEC.009"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_HIGH
    cwe = "CWE-295"
    message = "TLS certificate verification disabled"
    explanation = ("verify=False accepts any certificate, so an attacker positioned "
                   "on the network can read and modify the traffic while TLS still "
                   "appears to be in use.")
    remediation = "Leave verify at its default, or point it at a trusted CA bundle."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        if not call_name(node, ctx).startswith(("requests.", "httpx.")):
            return []
        for k in node.keywords:
            if k.arg != "verify":
                continue
            value = resolve_literal_name(k.value, ctx)
            if value is False:
                reason = ("verify=False passed explicitly"
                          if isinstance(k.value, ast.Constant)
                          else "verify variable resolves to False")
                return [self.make(ctx, node.lineno, node.col_offset,
                                  confidence_reason=reason)]
        return []


@register
class PyAssertForSecurity(Rule):
    id = "PY.SEC.010"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_MEDIUM
    cwe = "CWE-617"
    message = "assert used for a security check"
    explanation = ("Python removes assert statements entirely when run with -O, so a "
                   "security check written as an assert silently disappears in "
                   "optimised deployments.")
    remediation = "Use an explicit if statement that raises."
    GUARD = re.compile(r"(is_admin|is_auth|permission|role|access|allowed|authoriz|authentic|owner)", re.I)

    def check(self, node, ctx):
        if not isinstance(node, ast.Assert):
            return []
        text = ctx.line_text(node.lineno)
        if not self.GUARD.search(text):
            return []
        return [self.make(ctx, node.lineno, node.col_offset,
                          confidence_reason="assertion mentions an authorisation concept")]


@register
class PyDebugTrue(Rule):
    id = "PY.SEC.011"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_HIGH
    cwe = "CWE-489"
    message = "Web server started with debug=True"
    explanation = ("Debug mode exposes an interactive console and full tracebacks to "
                   "anyone who can reach the server, which can lead to code execution.")
    remediation = "Drive debug from configuration and keep it off in production."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        if dotted(node.func).split(".")[-1] != "run":
            return []
        for k in node.keywords:
            if k.arg == "debug" and is_const(k.value) and k.value.value is True:
                return [self.make(ctx, node.lineno, node.col_offset,
                                  confidence_reason="debug=True passed explicitly")]
        return []


@register
class PyPathTraversal(Rule):
    id = "PY.SEC.012"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-22"
    message = "File path built from untrusted input"
    explanation = ("If a path is assembled from user input, a value containing ../ "
                   "can escape the intended directory and reach unrelated files.")
    remediation = "Resolve the path and confirm it stays within an allowed base directory."

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        name = call_name(node, ctx)
        if name not in {"open", "os.path.join", "io.open"}:
            return []
        path = taint_path(node, ctx)
        if path:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_HIGH,
                              confidence_reason=f"untrusted input traced from line {path[0].line}",
                              taint_path=path)]
        # No proven path. A path *concatenated* from a variable is still worth
        # reporting, at lower confidence, because the taint engine is
        # intra-procedural and cannot see across a function boundary - the
        # common `def read(p): open(BASE + p)` case has no traceable source.
        # os.path.join is excluded: joining is the recommended practice and
        # flagging it would bury the signal.
        if name == "os.path.join" or not node.args:
            return []
        if not self._is_built_from_a_variable(node.args[0], ctx):
            return []
        return [self.make(ctx, node.lineno, node.col_offset,
                          confidence=CONF_MEDIUM,
                          confidence_reason="path is built by string construction; "
                                            "origin could not be traced")]

    @staticmethod
    def _fixed(node, ctx):
        """True if the node's value is known at analysis time.

        A module-level constant counts: `open(BASE + "f.txt")` splices nothing
        the caller controls, so it is not a traversal risk.
        """
        if is_const(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in ctx.constants
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return (PyPathTraversal._fixed(node.left, ctx)
                    and PyPathTraversal._fixed(node.right, ctx))
        return False

    @staticmethod
    def _is_built_from_a_variable(arg, ctx):
        """True for string construction that splices in a non-fixed value."""
        # "base/" + name
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
            return not PyPathTraversal._fixed(arg, ctx)
        # f"base/{name}"
        if isinstance(arg, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue)
                       and not PyPathTraversal._fixed(v.value, ctx)
                       for v in arg.values)
        # "base/{}".format(name)
        if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                and arg.func.attr == "format" and is_const(arg.func.value)):
            spliced = list(arg.args) + [k.value for k in arg.keywords]
            return any(not PyPathTraversal._fixed(a, ctx) for a in spliced)
        return False



@register
class PySSRF(Rule):
    id = "PY.SEC.013"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-918"
    message = "Potential server-side request forgery (SSRF)"
    explanation = ("A URL or host that originates from a request or other untrusted "
                   "source reaches an outbound HTTP client. An attacker may use this "
                   "to make the server request internal services or metadata endpoints.")
    remediation = "Allow-list destinations and validate scheme, host and resolved IP before requesting."
    HTTP_CALLS = {
        "requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch",
        "requests.request", "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
        "httpx.patch", "httpx.request", "urllib.request.urlopen", "urllib.request.Request",
    }

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        name = call_name(node, ctx)
        if name not in self.HTTP_CALLS:
            return []
        if not node.args and not any(k.arg == "url" for k in node.keywords):
            return []
        ta = getattr(ctx, "taint_analyzer", None)
        url = node.args[0] if node.args else next(k.value for k in node.keywords if k.arg == "url")
        path = taint_path(node, ctx) if ta else None
        if path:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_HIGH,
                              confidence_reason=f"untrusted URL traced from line {path[0].line}",
                              taint_path=path)]
        return []


@register
class PySensitiveLogging(Rule):
    id = "PY.SEC.014"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_MEDIUM
    cwe = "CWE-532"
    message = "Sensitive data may be written to logs"
    explanation = ("Logging passwords, API keys, session tokens or similar secrets can "
                   "expose credentials to log storage, support tooling and other readers.")
    remediation = "Log a safe identifier or event summary instead of the secret value."
    SENSITIVE = re.compile(
        r"(password|passwd|pwd|secret|api[_]?(key|token)|access[_]?token|refresh[_]?token|"
        r"private[_]?key|credential|client[_]?secret)", re.I)
    LOGGERS = {"print", "logging.debug", "logging.info", "logging.warning", "logging.error",
               "logging.exception", "logging.critical", "logger.debug", "logger.info",
               "logger.warning", "logger.error", "logger.exception", "logger.critical"}

    def check(self, node, ctx):
        if not isinstance(node, ast.Call):
            return []
        name = call_name(node, ctx)
        bare = name.split(".")[-1]
        if name not in self.LOGGERS and bare not in {"debug", "info", "warning", "error", "exception", "critical"}:
            return []
        names = [sub.id for arg in node.args for sub in ast.walk(arg)
                 if isinstance(sub, ast.Name) and self.SENSITIVE.search(sub.id)
                 and not SECRET_QUALIFIER.search(sub.id)]
        if not names:
            return []
        path = taint_path(node, ctx)
        if path:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_HIGH,
                              confidence_reason=f"sensitive value '{names[0]}' is traced to a logging sink",
                              taint_path=path)]
        # A strongly credential-specific identifier still merits a review even
        # when the value's origin is unknown, but generic `token` objects are not.
        if any(re.fullmatch(r"(password|passwd|pwd|secret|api[_]?(key|token)|access[_]?token|refresh[_]?token|private[_]?key|credential|client[_]?secret)", n, re.I) for n in names):
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_MEDIUM,
                              confidence_reason=f"credential-specific name '{names[0]}' is passed to a logging sink")]
        return []

@register
class PyInsecureTempfile(Rule):
    id = "PY.SEC.015"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_HIGH
    cwe = "CWE-377"
    message = "Insecure temporary-file creation"
    explanation = ("tempfile.mktemp() returns a filename without atomically creating the file. "
                   "Another process can race the name before the program opens it.")
    remediation = "Use tempfile.NamedTemporaryFile(), TemporaryDirectory(), or mkstemp()."

    def check(self, node, ctx):
        if isinstance(node, ast.Call) and call_name(node, ctx) in {"tempfile.mktemp", "mktemp"}:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence_reason="mktemp() creates a predictable race window")]
        return []


@register
class PyWorldWritable(Rule):
    id = "PY.SEC.016"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_HIGH
    cwe = "CWE-732"
    message = "World-writable file permissions"
    explanation = ("Permissions such as 0o777 or 0o666 grant broad write access. In shared "
                   "systems this can let other users replace or tamper with the file.")
    remediation = "Use the least-privilege mode required, such as 0o600 or 0o640."
    CHMOD = {"os.chmod", "chmod"}

    def check(self, node, ctx):
        if not isinstance(node, ast.Call) or call_name(node, ctx) not in self.CHMOD or len(node.args) < 2:
            return []
        mode = resolve_literal_name(node.args[1], ctx)
        if not isinstance(mode, int):
            return []
        if mode & 0o002:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_HIGH,
                              confidence_reason=f"chmod mode resolves to {oct(mode)} and grants write access to others")]
        if mode & 0o020:
            return [self.make(ctx, node.lineno, node.col_offset,
                              confidence=CONF_MEDIUM,
                              confidence_reason=f"chmod mode resolves to {oct(mode)} and grants write access to the group")]
        return []


@register
class PyTarExtract(Rule):
    id = "PY.SEC.017"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-22"
    message = "Tar extraction relies on a version-dependent safety filter"
    explanation = ("Tar extraction behavior changed in Python 3.14: the default filter became "
                   "'data'. On older supported Python versions, omitting a filter can allow unsafe "
                   "archive members; an explicit 'data' filter is portable and clearer.")
    remediation = "Use filter='data' explicitly and validate extraction paths."
    TAR_METHODS = {"tarfile.extractall", "TarFile.extractall"}

    def check(self, node, ctx):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "extractall":
            return []
        receiver = dotted(node.func.value)
        if receiver and receiver.split(".")[-1].lower() not in {"tar", "tarfile", "tf", "archive"} and "tar" not in receiver.lower():
            return []
        has_filter = False
        unsafe_filter = False
        for k in node.keywords:
            if k.arg == "filter":
                has_filter = True
                if isinstance(k.value, ast.Constant) and k.value.value in {None, "fully_trusted"}:
                    unsafe_filter = True
        if unsafe_filter:
            return [self.make(
                ctx, node.lineno, node.col_offset, confidence=CONF_HIGH,
                message="Tar extraction explicitly disables safety filtering",
                confidence_reason="filter=None/fully_trusted disables the archive safety filter",
            )]
        if not has_filter:
            return [self.make(
                ctx, node.lineno, node.col_offset, confidence=CONF_LOW,
                confidence_reason="no explicit filter makes archive safety depend on the Python runtime version",
            )]
        return []



# ══════════════════════════════════════════════════════════ quality rules
@register
class PyBareExcept(Rule):
    id = "PY.QUAL.001"
    language = LANG
    category = "quality"
    severity = MEDIUM
    base_confidence = CONF_HIGH
    cwe = "CWE-396"
    message = "Bare 'except:' catches every error"
    explanation = ("A bare except swallows everything, including KeyboardInterrupt "
                   "and genuine bugs like typos, so real failures disappear silently.")
    remediation = "Catch a specific exception, e.g. 'except ValueError:'."
    fixable = True

    def check(self, node, ctx):
        if not isinstance(node, ast.ExceptHandler) or node.type is not None:
            return []
        line = ctx.line_text(node.lineno)
        col = node.col_offset
        fix = None
        if line.startswith("except") and line.rstrip().endswith(":"):
            fix = Edit(line=node.lineno, col=col,
                       end_line=node.lineno, end_col=col + len("except:"),
                       replacement="except Exception:",
                       describe="catch Exception instead of everything")
        return [self.make(ctx, node.lineno, col,
                          confidence_reason="except clause names no exception type", fix=fix)]


@register
class PyMutableDefault(Rule):
    id = "PY.QUAL.002"
    language = LANG
    category = "quality"
    severity = MEDIUM
    base_confidence = CONF_HIGH
    message = "Mutable default argument"
    explanation = ("Default arguments are created once, when the function is defined - "
                   "not on each call. A list or dict default is therefore shared "
                   "between calls and accumulates state.")
    remediation = "Use None as the default and build the container inside the function."

    def check(self, node, ctx):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d]
        for d in defaults:
            bad = isinstance(d, (ast.List, ast.Dict, ast.Set))
            if isinstance(d, ast.Call) and dotted(d.func) in {"list", "dict", "set", "collections.OrderedDict"}:
                bad = True
            if bad:
                return [self.make(ctx, node.lineno, node.col_offset,
                                  message=f"Mutable default argument in '{node.name}'",
                                  confidence_reason="default value is a mutable literal or constructor")]
        return []


@register
class PyUnusedImport(Rule):
    id = "PY.QUAL.003"
    language = LANG
    category = "quality"
    severity = LOW
    base_confidence = CONF_MEDIUM
    message = "Unused import"
    explanation = ("An import that is never referenced adds a dependency and load "
                   "time for no benefit, and hides which modules are really needed.")
    remediation = "Remove the import."
    fixable = True

    def check(self, node, ctx):
        if not isinstance(node, ast.Module):
            return []
        used = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        for a in ast.walk(node):
            if isinstance(a, ast.Attribute):
                d = dotted(a)
                if d:
                    used.add(d.split(".")[0])
        # names referenced from strings (__all__, type comments) are ignored
        out = []
        for stmt in ast.walk(node):
            if not isinstance(stmt, (ast.Import, ast.ImportFrom)):
                continue
            if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
                continue
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                local = (alias.asname or alias.name).split(".")[0]
                if local in used:
                    continue
                only = len(stmt.names) == 1
                fix = None
                if only:
                    fix = Edit(line=stmt.lineno, col=0,
                               end_line=getattr(stmt, "end_lineno", stmt.lineno),
                               end_col=None, replacement="",
                               describe=f"remove unused import '{local}'")
                out.append(self.make(
                    ctx, stmt.lineno, stmt.col_offset,
                    message=f"'{local}' is imported but never used",
                    confidence_reason="name never appears in a load context in this file",
                    fix=fix,
                ))
        return out


@register
class PySingletonCompare(Rule):
    id = "PY.QUAL.004"
    language = LANG
    category = "quality"
    severity = LOW
    base_confidence = CONF_HIGH
    message = "Comparison to None/True/False with =="
    explanation = ("Singletons should be compared by identity. A class that overrides "
                   "__eq__ can make `x == None` return True for a non-None value.")
    remediation = "Use 'is' / 'is not'."
    fixable = True

    def check(self, node, ctx):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            return []
        op = node.ops[0]
        if not isinstance(op, (ast.Eq, ast.NotEq)):
            return []
        rhs = node.comparators[0]
        if not (is_const(rhs) and (rhs.value is None or rhs.value is True or rhs.value is False)):
            return []
        left_end_line = getattr(node.left, "end_lineno", node.lineno)
        left_end_col = getattr(node.left, "end_col_offset", None)
        fix = None
        if left_end_col is not None and getattr(rhs, "col_offset", None) is not None \
                and left_end_line == rhs.lineno:
            fix = Edit(line=left_end_line, col=left_end_col,
                       end_line=rhs.lineno, end_col=rhs.col_offset,
                       replacement=" is " if isinstance(op, ast.Eq) else " is not ",
                       describe="use identity comparison")
        word = "==" if isinstance(op, ast.Eq) else "!="
        return [self.make(ctx, node.lineno, node.col_offset,
                          message=f"Comparison to {rhs.value!r} using {word}",
                          confidence_reason="right-hand side is a singleton constant",
                          fix=fix)]


@register
class PyComplexity(Rule):
    id = "PY.QUAL.005"
    language = LANG
    category = "quality"
    severity = MEDIUM
    base_confidence = CONF_HIGH
    message = "Function is too complex"
    explanation = ("Each branch multiplies the paths through a function. Beyond "
                   "roughly ten, functions become hard to test exhaustively and "
                   "defects concentrate in them.")
    remediation = "Extract branches into named helper functions."
    MAX = 10

    def check(self, node, ctx):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        score = 1
        for sub in ast.walk(node):
            if isinstance(sub, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                                ast.With, ast.Assert, ast.IfExp)):
                score += 1
            elif isinstance(sub, ast.BoolOp):
                score += len(sub.values) - 1
        if score <= self.MAX:
            return []
        return [self.make(ctx, node.lineno, node.col_offset,
                          message=f"Function '{node.name}' has cyclomatic complexity {score}",
                          confidence_reason=f"counted {score} independent branches")]


# ════════════════════════════════════════════════════════════ style rules
@register
class PyNaming(Rule):
    id = "PY.STYLE.001"
    language = LANG
    category = "style"
    severity = LOW
    base_confidence = CONF_HIGH
    message = "Name does not follow PEP 8"
    explanation = ("PEP 8 is lower_snake_case for functions and PascalCase for "
                   "classes. Consistent naming makes a shared codebase readable.")
    remediation = "Rename to match the convention."

    def check(self, node, ctx):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not SNAKE.match(node.name):
                return [self.make(ctx, node.lineno, node.col_offset,
                                  message=f"Function '{node.name}' is not snake_case",
                                  confidence_reason="name fails the PEP 8 function pattern")]
        elif isinstance(node, ast.ClassDef):
            if not PASCAL.match(node.name):
                return [self.make(ctx, node.lineno, node.col_offset,
                                  message=f"Class '{node.name}' is not PascalCase",
                                  confidence_reason="name fails the PEP 8 class pattern")]
        return []


@register
class PyLineLength(Rule):
    id = "PY.STYLE.002"
    language = LANG
    category = "style"
    severity = LOW
    base_confidence = CONF_HIGH
    message = "Line is too long"
    explanation = ("Very long lines are hard to read in side-by-side diffs and force "
                   "horizontal scrolling during review.")
    remediation = "Wrap the line, ideally under 100 characters."
    MAX = 100

    def check(self, node, ctx):
        if not isinstance(node, ast.Module):
            return []
        out = []
        for i, line in enumerate(ctx.lines, start=1):
            if len(line) > self.MAX:
                out.append(self.make(
                    ctx, i, self.MAX,
                    message=f"Line is {len(line)} characters (limit {self.MAX})",
                    confidence_reason="measured directly from the source line",
                ))
        return out


@register
class PyFunctionSize(Rule):
    id = "PY.STYLE.003"
    language = LANG
    category = "style"
    severity = LOW
    base_confidence = CONF_HIGH
    message = "Function is long or takes many parameters"
    explanation = ("Long parameter lists and long bodies are a reliable signal that a "
                   "function is doing more than one job.")
    remediation = "Split the function, or group parameters into a dataclass."
    MAX_LINES = 60
    MAX_PARAMS = 6

    def check(self, node, ctx):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        span = getattr(node, "end_lineno", node.lineno) - node.lineno
        nparams = len(node.args.args) + len(node.args.kwonlyargs) + len(node.args.posonlyargs)
        issues = []
        if span > self.MAX_LINES:
            issues.append(f"{span} lines")
        if nparams > self.MAX_PARAMS:
            issues.append(f"{nparams} parameters")
        if not issues:
            return []
        return [self.make(ctx, node.lineno, node.col_offset,
                          message=f"Function '{node.name}' has " + " and ".join(issues),
                          confidence_reason="measured from the parsed function definition")]
