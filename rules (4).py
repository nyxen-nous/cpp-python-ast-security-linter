"""
C++ rules.

Each rule matches against structural nodes produced by parser.py, never
against raw text. The `bare` name of a call has already had any namespace
or member qualification stripped, so `std::system(...)` and `system(...)`
both match, while the word `system` inside a comment matches nothing.
"""

import re

from ..core.finding import (
    CRITICAL, HIGH, MEDIUM, LOW,
    CONF_HIGH, CONF_MEDIUM, CONF_LOW,
)
from ..core.rule import Rule, register
from .lexer import IDENT, NUMBER, STRING, string_body
from .parser import (
    CALL_EXPR, DECLARATION, FUNCTION_DEF, NEW_EXPR, DELETE_EXPR,
    USING_DECL, PREPROC_NODE,
)

LANG = "cpp"

from ..core.patterns import SECRET_NAME, SECRET_QUALIFIER



def _arg_is_literal(arg_tokens):
    """True when an argument is a compile-time constant expression."""
    meaningful = [t for t in arg_tokens if t.kind != "comment"]
    if not meaningful:
        return False
    return all(t.kind in (STRING, NUMBER) or t.is_op("+", "-", "*", "/")
               or t.is_kw("sizeof") for t in meaningful)


def _arg_is_compile_time_bound(arg_tokens):
    """True for literal-like lengths, including sizeof(name).

    `sizeof(buffer)` is a compile-time bound even though it contains an
    identifier. Treating it as runtime data is a noisy false positive for the
    memcpy rule, while arbitrary identifiers remain runtime and are flagged.
    """
    meaningful = [t for t in arg_tokens if t.kind != "comment"]
    if not meaningful:
        return False
    if _arg_is_literal(meaningful):
        return True
    if len(meaningful) >= 4 and meaningful[0].is_kw("sizeof") and meaningful[1].is_op("(") and meaningful[-1].is_op(")"):
        inner = meaningful[2:-1]
        return len(inner) >= 1 and all(t.kind == IDENT or t.is_op("::", "->", ".") for t in inner)
    if len(meaningful) >= 2 and meaningful[0].is_kw("sizeof"):
        inner = meaningful[1:]
        return all(t.kind == IDENT or t.is_op("::", "->", ".") for t in inner)
    return False


# ═══════════════════════════════════════════════════════ security rules
@register
class CppGets(Rule):
    id = "CPP.SEC.001"
    language = LANG
    category = "security"
    severity = CRITICAL
    base_confidence = CONF_HIGH
    cwe = "CWE-242"
    message = "gets() cannot be used safely"
    explanation = ("gets() has no way to know how large the destination buffer is, "
                   "so any input longer than the buffer overflows it. It was removed "
                   "from the C standard entirely.")
    remediation = "Use fgets(buf, sizeof(buf), stdin) instead."

    def check(self, node, ctx):
        if node.type == CALL_EXPR and node.extra.get("bare") == "gets":
            return [self.make(ctx, node.line, node.col,
                              confidence_reason="gets() is unsafe regardless of arguments")]
        return []


@register
class CppUnboundedCopy(Rule):
    id = "CPP.SEC.002"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-120"
    message = "Unbounded string copy"
    explanation = ("strcpy, strcat and sprintf keep writing until they reach a "
                   "terminating null byte. If the source is longer than the "
                   "destination, memory past the buffer is overwritten.")
    remediation = "Use the bounded forms: strncpy, strncat, snprintf."
    UNSAFE = {"strcpy", "strcat", "sprintf", "vsprintf", "wcscpy", "wcscat"}

    def check(self, node, ctx):
        if node.type == CALL_EXPR and node.extra.get("bare") in self.UNSAFE:
            fn = node.extra["bare"]
            return [self.make(ctx, node.line, node.col,
                              message=f"Unbounded copy via {fn}()",
                              confidence_reason="destination size is not passed to the call")]
        return []


@register
class CppSystemCall(Rule):
    id = "CPP.SEC.003"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-78"
    message = "Shell command execution"
    explanation = ("system() and popen() hand the string to a shell. If any part of "
                   "it comes from user input, characters like ; or | let an attacker "
                   "append their own commands.")
    remediation = "Use exec-family calls with an argument array, avoiding the shell."
    UNSAFE = {"system", "popen", "_popen"}

    def check(self, node, ctx):
        if node.type != CALL_EXPR or node.extra.get("bare") not in self.UNSAFE:
            return []
        args = node.extra.get("args") or []
        literal = args and _arg_is_literal(args[0])
        return [self.make(
            ctx, node.line, node.col,
            message=f"Shell execution via {node.extra['bare']}()",
            confidence=CONF_LOW if literal else CONF_MEDIUM,
            confidence_reason=("argument is a compile-time constant"
                               if literal else "argument is not a constant"),
        )]


@register
class CppScanfNoWidth(Rule):
    id = "CPP.SEC.004"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_HIGH
    cwe = "CWE-120"
    message = "scanf(\"%s\") without a field width"
    explanation = ("A bare %s in scanf reads until whitespace with no bound, so a "
                   "long input overflows the destination buffer.")
    remediation = "Give %s an explicit width, e.g. %63s for a 64-byte buffer."
    FAMILY = {"scanf", "fscanf", "sscanf"}
    BARE_S = re.compile(r"%\*?s")

    def check(self, node, ctx):
        if node.type != CALL_EXPR or node.extra.get("bare") not in self.FAMILY:
            return []
        args = node.extra.get("args") or []
        for arg in args:
            for t in arg:
                if t.kind == STRING and self.BARE_S.search(string_body(t)):
                    return [self.make(ctx, node.line, node.col,
                                      confidence_reason="format string contains %s with no width")]
        return []


@register
class CppWeakRandom(Rule):
    id = "CPP.SEC.005"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_LOW
    cwe = "CWE-338"
    message = "rand() is not cryptographically secure"
    explanation = ("rand() is a predictable pseudo-random generator. Given a few "
                   "outputs an attacker can predict the rest, so it must not be "
                   "used for tokens, keys, passwords or nonces.")
    remediation = "Use std::random_device or a platform CSPRNG for security values."

    SENSITIVE = SECRET_NAME

    def check(self, node, ctx):
        if node.type != CALL_EXPR or node.extra.get("bare") not in {"rand", "srand"}:
            return []
        # Flag rand() strongly only when its result feeds a security-looking name.
        toks = node.tokens or []
        names = {t.value for t in toks if t.kind == IDENT}
        owner = getattr(node, "parent", None)
        owner_name = getattr(owner, "name", "")
        sensitive = any(self.SENSITIVE.search(name) for name in names) or bool(self.SENSITIVE.search(owner_name))
        if not sensitive:
            return []
        return [self.make(
            ctx, node.line, node.col, confidence=CONF_MEDIUM,
            message="Weak randomness used for a security-sensitive value",
            confidence_reason="rand()/srand() appears in an assignment/declaration using a credential-like identifier",
        )]


@register
class CppFormatString(Rule):
    id = "CPP.SEC.006"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-134"
    message = "Non-literal format string"
    explanation = ("When the format argument is a variable, an attacker who controls "
                   "it can insert %x to read memory or %n to write to it.")
    remediation = 'Use a literal format: printf("%s", value).'
    FAMILY = {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "syslog"}

    def check(self, node, ctx):
        if node.type != CALL_EXPR or node.extra.get("bare") not in self.FAMILY:
            return []
        args = node.extra.get("args") or []
        idx = 1 if node.extra["bare"] in {"fprintf", "syslog"} else 0
        if node.extra["bare"] in {"sprintf", "snprintf"}:
            idx = 1 if node.extra["bare"] == "sprintf" else 2
        if len(args) <= idx:
            return []
        fmt = [t for t in args[idx]]
        if len(fmt) == 1 and fmt[0].kind == IDENT:
            return [self.make(ctx, node.line, node.col,
                              message=f"{node.extra['bare']}() called with a variable format string",
                              confidence_reason="format argument is an identifier, not a literal")]
        return []


@register
class CppMemcpyUnchecked(Rule):
    id = "CPP.SEC.007"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_LOW
    cwe = "CWE-787"
    message = "memcpy with a non-constant length"
    explanation = ("When the length argument is computed at runtime, nothing here "
                   "guarantees it fits the destination. This is a common source of "
                   "out-of-bounds writes.")
    remediation = "Bound the length against sizeof(destination) before copying."
    FAMILY = {"memcpy", "memmove", "wmemcpy"}

    def check(self, node, ctx):
        if node.type != CALL_EXPR or node.extra.get("bare") not in self.FAMILY:
            return []
        args = node.extra.get("args") or []
        if len(args) < 3 or _arg_is_compile_time_bound(args[2]):
            return []
        # Constant/explicitly-sized copies are safe enough for this lightweight rule.
        return [self.make(
            ctx, node.line, node.col, confidence=CONF_LOW,
            confidence_reason="length is runtime-controlled and this rule cannot prove a destination bound",
        )]


@register
class CppNewWithoutDelete(Rule):
    id = "CPP.SEC.008"
    language = LANG
    category = "security"
    severity = MEDIUM
    base_confidence = CONF_LOW
    cwe = "CWE-401"
    message = "Possible raw-allocation leak"
    explanation = ("A raw allocation has no matching delete in this function. This is a "
                   "conservative lifetime heuristic; ownership may be transferred elsewhere.")
    remediation = "Prefer std::unique_ptr / std::vector so cleanup is automatic."

    def check(self, node, ctx):
        if node.type != FUNCTION_DEF:
            return []
        all_news = [n for n in node.walk() if n.type == NEW_EXPR]
        dels = [n for n in node.walk() if n.type == DELETE_EXPR]

        # Common RAII ownership patterns are intentionally excluded: the rule
        # is about leaked raw ownership, not a `new` whose lifetime is managed
        # immediately by unique_ptr/shared_ptr.
        news = []
        values = _token_values(node.tokens or [])
        returned_new_lines = {
            node.tokens[i].line for i in range(1, len(node.tokens))
            if values[i] == "new" and values[i - 1] == "return"
        }
        for n in all_news:
            # Ownership is transferred when the allocation is directly returned.
            # A same-function-only leak check must not treat that as a leak.
            if n.line in returned_new_lines:
                continue
            parent = n.parent
            managed = False
            if parent is not None and parent.type == "declaration":
                type_words = [t.value for t in parent.tokens]
                managed = any(w in {"unique_ptr", "shared_ptr", "weak_ptr", "make_unique", "make_shared"}
                              for w in type_words)
                if not managed:
                    # The lightweight parser may start the declaration at the
                    # template argument (`int > p(new int)`). Fall back to the
                    # original source line to identify common RAII wrappers.
                    line_text = ctx.line_text(n.line)
                    managed = any(w in line_text for w in (
                        "unique_ptr<", "shared_ptr<", "weak_ptr<",
                        "make_unique(", "make_shared("))
            # Constructor-style ownership: std::unique_ptr<T>(new T(...))
            if not managed and parent is not None and parent.type == "call_expression":
                managed = parent.extra.get("bare") in {"unique_ptr", "shared_ptr", "make_unique", "make_shared"}
            if not managed:
                news.append(n)

        if news and len(dels) < len(news):
            first = news[0]
            return [self.make(
                ctx, first.line, first.col,
                message=f"{len(news)} raw allocation(s), {len(dels)} delete(s) in '{node.name}'",
                confidence_reason="intra-function heuristic; known RAII smart-pointer ownership is excluded",
            )]
        return []


@register
class CppHardcodedSecret(Rule):
    id = "CPP.SEC.009"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-798"
    message = "Possible hard-coded credential"
    explanation = ("A string literal assigned to a credential-named variable ends up "
                   "in the compiled binary and in version control, where it can be "
                   "extracted with a strings dump.")
    remediation = "Read secrets from the environment or a secrets manager at runtime."

    def check(self, node, ctx):
        if node.type != DECLARATION or not SECRET_NAME.search(node.name):
            return []
        if SECRET_QUALIFIER.search(node.name):
            return []
        init = node.extra.get("init") or []
        lits = [t for t in init if t.kind == STRING]
        if not lits:
            return []
        body = string_body(lits[0])
        if len(body) < 6:
            return []
        return [self.make(
            ctx, node.line, node.col,
            message=f"Possible hard-coded secret in '{node.name}'",
            confidence_reason="variable name matches a credential pattern and the value is a literal",
        )]


# ════════════════════════════════════════════════ quality / style rules


# ═════════════════════════════════════════════════════════ advanced memory rules

def _fn_tokens(node):
    return list(node.tokens or []) if node.type == FUNCTION_DEF else []


def _token_values(tokens):
    return [t.value for t in tokens]


def _prev_value(values, i):
    return values[i - 1] if i > 0 else None


@register
class CppUseAfterFree(Rule):
    id = "CPP.SEC.010"
    language = LANG
    category = "security"
    severity = CRITICAL
    base_confidence = CONF_HIGH
    cwe = "CWE-416"
    message = "Potential use-after-free"
    explanation = ("A pointer is explicitly deleted and then dereferenced later in the same "
                   "function without an intervening reassignment. The later access may read "
                   "freed memory and cause corruption or code execution.")
    remediation = "Stop using the pointer after delete, or transfer ownership to an RAII smart pointer."

    def check(self, node, ctx):
        if node.type != FUNCTION_DEF:
            return []
        toks = _fn_tokens(node)
        deleted = {}
        values = _token_values(toks)
        out = []
        for i, t in enumerate(toks):
            v = t.value
            if v == "delete":
                j = i + 1
                if j + 1 < len(toks) and toks[j].value == "[" and toks[j + 1].value == "]":
                    j += 2
                if j < len(toks) and toks[j].kind == "identifier":
                    deleted[toks[j].value] = i
                continue
            if v in {"=", "->", "["} and v == "=" and i + 1 < len(toks):
                # A direct reassignment clears the old lifetime state.
                lhs = toks[i - 1].value if i > 0 and toks[i - 1].kind == "identifier" else None
                if lhs in deleted:
                    deleted.pop(lhs, None)
            for name, di in list(deleted.items()):
                if i <= di:
                    continue
                if (v == "*" and i + 1 < len(toks) and toks[i + 1].value == name) or \
                   (v == name and _prev_value(values, i) in {"->", "["}) or \
                   (v == name and i + 1 < len(toks) and toks[i + 1].value == "["):
                    out.append(self.make(ctx, t.line, t.col,
                                         message=f"Pointer '{name}' is used after delete",
                                         confidence_reason=f"'{name}' was deleted earlier in this function"))
                    deleted.pop(name, None)
                    break
        return out


@register
class CppDoubleFree(Rule):
    id = "CPP.SEC.011"
    language = LANG
    category = "security"
    severity = CRITICAL
    base_confidence = CONF_HIGH
    cwe = "CWE-415"
    message = "Potential double free"
    explanation = ("The same pointer is freed more than once in the same function without an "
                   "intervening reassignment. A second free/delete can corrupt the allocator.")
    remediation = "Set ownership to one owner and release memory exactly once; prefer RAII."

    def check(self, node, ctx):
        if node.type != FUNCTION_DEF:
            return []
        toks = _fn_tokens(node)
        freed = set()
        out = []
        for i, t in enumerate(toks):
            if t.value == "delete":
                j = i + 1
                if j + 1 < len(toks) and toks[j].value == "[" and toks[j + 1].value == "]":
                    j += 2
                if j >= len(toks) or toks[j].kind != "identifier":
                    i += 1
                    continue
                name = toks[j].value
                if name in freed:
                    out.append(self.make(ctx, t.line, t.col,
                                         message=f"Pointer '{name}' is deleted more than once",
                                         confidence_reason=f"'{name}' was already deleted earlier in this function"))
                freed.add(name)
            elif t.value == "free" and i + 2 < len(toks) and toks[i + 1].value == "(":
                if toks[i + 2].kind == "identifier":
                    name = toks[i + 2].value
                    if name in freed:
                        out.append(self.make(ctx, t.line, t.col,
                                             message=f"Pointer '{name}' may be freed more than once",
                                             confidence_reason=f"'{name}' was already freed earlier in this function"))
                    freed.add(name)
            elif t.value == "=" and i > 0 and toks[i - 1].kind == "identifier":
                freed.discard(toks[i - 1].value)
        return out


@register
class CppUninitializedLocal(Rule):
    id = "CPP.SEC.012"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-457"
    message = "Local variable may be used before initialization"
    explanation = ("A local scalar declaration has no initializer and is read later before this "
                   "function assigns it. The value can therefore be indeterminate.")
    remediation = "Initialize the variable at declaration or guarantee assignment on every path."
    TYPES = {"int", "char", "short", "long", "float", "double", "bool", "size_t", "unsigned", "signed"}

    def check(self, node, ctx):
        if node.type != FUNCTION_DEF:
            return []
        toks = _fn_tokens(node)
        pending = {}
        out = []
        i = 0
        while i < len(toks) - 1:
            t = toks[i]
            if t.kind == "identifier" and t.value in self.TYPES:
                j = i + 1
                while j < len(toks) and toks[j].value in {"const", "unsigned", "signed", "long"}:
                    j += 1
                if j < len(toks) and toks[j].kind == "identifier":
                    name = toks[j].value
                    if j + 1 < len(toks) and toks[j + 1].value == ";":
                        pending[name] = j
                        i = j + 1
                        continue
            if t.kind == "identifier" and t.value in pending:
                # assignment to the variable clears the warning
                if i + 1 < len(toks) and toks[i + 1].value == "=":
                    pending.pop(t.value, None)
                elif i > 0 and toks[i - 1].value in {"*", "&"}:
                    pass
                elif i > 0 and toks[i - 1].value == "sizeof":
                    pass
                else:
                    out.append(self.make(ctx, t.line, t.col,
                                         message=f"'{t.value}' may be read before initialization",
                                         confidence_reason=f"'{t.value}' was declared without an initializer and no assignment was seen before this use"))
                    pending.pop(t.value, None)
            i += 1
        return out


@register
class CppUncontrolledAllocation(Rule):
    id = "CPP.SEC.013"
    language = LANG
    category = "security"
    severity = HIGH
    base_confidence = CONF_MEDIUM
    cwe = "CWE-789"
    message = "Allocation size is controlled by a runtime value"
    explanation = ("A dynamic array allocation uses a non-constant size. If the value comes "
                   "from untrusted input or has no upper bound, an attacker may force excessive "
                   "memory consumption or trigger allocation-related failures.")
    remediation = "Validate and cap the requested size before allocating memory."

    def check(self, node, ctx):
        if node.type != FUNCTION_DEF:
            return []
        toks = _fn_tokens(node)
        for i, t in enumerate(toks):
            if t.value == "new" and i + 4 < len(toks):
                # Find the first bracketed array extent after new.
                for j in range(i + 1, min(i + 12, len(toks) - 2)):
                    if toks[j].value == "[" and toks[j + 1].kind == "identifier":
                        if toks[j + 2].value == "]":
                            return [self.make(ctx, t.line, t.col,
                                              confidence=CONF_MEDIUM,
                                              confidence_reason=f"array extent uses runtime identifier '{toks[j+1].value}'")]
                    if toks[j].value == ";":
                        break
        return []


@register
class CppNullDeref(Rule):
    id = "CPP.SEC.014"
    language = LANG
    category = "security"
    severity = CRITICAL
    base_confidence = CONF_HIGH
    cwe = "CWE-476"
    message = "Possible null-pointer dereference"
    explanation = ("A pointer is explicitly assigned nullptr and then dereferenced without a "
                   "reassignment. The dereference is therefore known to target a null value.")
    remediation = "Check the pointer before dereferencing it or handle the null case explicitly."

    def check(self, node, ctx):
        if node.type != FUNCTION_DEF:
            return []
        toks = _fn_tokens(node)
        nulled = set()
        out = []
        i = 0
        # Ignore function signature and inspect only the body after the first '{'.
        while i < len(toks) and toks[i].value != "{":
            i += 1
        i += 1
        while i < len(toks):
            t = toks[i]
            if (t.kind == "identifier" and i + 2 < len(toks)
                    and toks[i + 1].value == "=" and toks[i + 2].value in {"nullptr", "NULL"}):
                nulled.add(t.value)
                i += 3
                continue
            if t.value == "=" and i > 0 and toks[i - 1].kind == "identifier":
                nulled.discard(toks[i - 1].value)
                i += 1
                continue
            hit = None
            if t.value == "*" and i + 1 < len(toks) and toks[i + 1].value in nulled:
                hit = toks[i + 1].value
            elif t.kind == "identifier" and t.value in nulled:
                if i > 0 and toks[i - 1].value == "->":
                    hit = t.value
                elif i + 1 < len(toks) and toks[i + 1].value == "[":
                    hit = t.value
            if hit:
                out.append(self.make(
                    ctx, t.line, t.col,
                    message=f"Pointer '{hit}' is dereferenced after being set to null",
                    confidence_reason=f"'{hit}' was explicitly assigned nullptr/NULL before this dereference",
                ))
                nulled.discard(hit)
            i += 1
        return out


@register
class CppUsingNamespaceInHeader(Rule):
    id = "CPP.QUAL.001"
    language = LANG
    category = "quality"
    severity = LOW
    base_confidence = CONF_HIGH
    message = "'using namespace' at file scope in a header"
    explanation = ("A using-directive in a header leaks into every file that "
                   "includes it, which can silently change overload resolution in "
                   "code the header author never sees.")
    remediation = "Qualify names explicitly, or keep the using-directive inside a .cpp file."

    def check(self, node, ctx):
        if node.type != USING_DECL or "namespace" not in node.name:
            return []
        if not ctx.filename.lower().endswith((".h", ".hpp", ".hh", ".hxx")):
            return []
        return [self.make(ctx, node.line, node.col,
                          confidence_reason="file extension indicates a header")]


@register
class CppMissingIncludeGuard(Rule):
    id = "CPP.QUAL.002"
    language = LANG
    category = "quality"
    severity = MEDIUM
    base_confidence = CONF_HIGH
    message = "Header has no include guard"
    explanation = ("Without a guard, including this header twice in one translation "
                   "unit produces duplicate definition errors.")
    remediation = "Add #pragma once, or a classic #ifndef / #define / #endif guard."

    def check(self, node, ctx):
        if node.type != "translation_unit":
            return []
        if not ctx.filename.lower().endswith((".h", ".hpp", ".hh", ".hxx")):
            return []
        for d in node.children:
            if d.type != PREPROC_NODE:
                continue
            text = d.extra.get("text", "")
            if "pragma once" in text or text.startswith("#ifndef") or text.startswith("#if !"):
                return []
        return [self.make(ctx, 1, 0,
                          confidence_reason="no #pragma once or #ifndef guard found")]


@register
class CppFunctionSize(Rule):
    id = "CPP.STYLE.001"
    language = LANG
    category = "style"
    severity = LOW
    base_confidence = CONF_HIGH
    message = "Function is long or takes too many parameters"
    explanation = ("Long functions with many parameters are harder to test and "
                   "review, and reviewers miss bugs in them more often.")
    remediation = "Split the function, or group related parameters into a struct."
    MAX_LINES = 60
    MAX_PARAMS = 6

    def check(self, node, ctx):
        if node.type != FUNCTION_DEF:
            return []
        span = node.extra.get("end_line", node.line) - node.line
        params = [p for p in node.extra.get("params", []) if p]
        issues = []
        if span > self.MAX_LINES:
            issues.append(f"{span} lines")
        if len(params) > self.MAX_PARAMS:
            issues.append(f"{len(params)} parameters")
        if not issues:
            return []
        return [self.make(ctx, node.line, node.col,
                          message=f"Function '{node.name}' has " + " and ".join(issues),
                          confidence_reason="measured from the parsed function body")]
