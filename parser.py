"""
A structural parser for C++.

This does not attempt to be a full C++ compiler front end - that problem is
genuinely enormous (templates, overload resolution, the preprocessor). It
builds the structure a linter actually needs:

    translation_unit
      preproc_directive
      function_definition   name, parameters, body span, brace depth
        call_expression     callee, argument token spans
        declaration         declared name and its initialiser
        new_expression / delete_expression
        control_flow        if / for / while / switch

Every node carries a real line and column, and every node was produced from
a token stream in which comments and string literals were already separated
out - so a match can never come from a comment or a quoted string.

The node interface mirrors the shape a Tree-sitter tree would expose
(`type`, `children`, `line`, `col`), so swapping in a Tree-sitter backend
later is a parser change and not a rule rewrite.
"""

from .lexer import tokenize, Token, IDENT, NUMBER, STRING, CHAR, PREPROC, PUNCT, EOF

TRANSLATION_UNIT = "translation_unit"
FUNCTION_DEF = "function_definition"
CALL_EXPR = "call_expression"
DECLARATION = "declaration"
NEW_EXPR = "new_expression"
DELETE_EXPR = "delete_expression"
CONTROL = "control_flow"
PREPROC_NODE = "preproc_directive"
USING_DECL = "using_declaration"
CAST_EXPR = "cast_expression"

CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch"}
# things that look like a call but are language constructs
NON_CALL_KEYWORDS = CONTROL_KEYWORDS | {"return", "sizeof", "throw", "operator", "decltype"}
TYPE_WORDS = {
    "void", "int", "char", "short", "long", "float", "double", "bool",
    "unsigned", "signed", "const", "static", "inline", "virtual", "extern",
    "constexpr", "auto", "struct", "class", "template", "typename", "explicit",
}


class Node:
    __slots__ = ("type", "line", "col", "name", "children", "tokens", "parent", "extra")

    def __init__(self, type_, line, col, name="", tokens=None, extra=None):
        self.type = type_
        self.line = line
        self.col = col
        self.name = name
        self.children = []
        self.tokens = tokens or []
        self.parent = None
        self.extra = extra or {}

    def add(self, child):
        child.parent = self
        self.children.append(child)
        return child

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def find(self, *types):
        for n in self.walk():
            if n.type in types:
                yield n

    def enclosing(self, *types):
        p = self.parent
        while p is not None:
            if p.type in types:
                return p
            p = p.parent
        return None

    def __repr__(self):
        return f"<{self.type} {self.name!r} @{self.line}>"


# ----------------------------------------------------------------- helpers
def _match_paren(tokens, i):
    """Index of the ')' matching the '(' at position i, or -1."""
    depth = 0
    for j in range(i, len(tokens)):
        if tokens[j].is_op("("):
            depth += 1
        elif tokens[j].is_op(")"):
            depth -= 1
            if depth == 0:
                return j
    return -1


def _match_brace(tokens, i):
    depth = 0
    for j in range(i, len(tokens)):
        if tokens[j].is_op("{"):
            depth += 1
        elif tokens[j].is_op("}"):
            depth -= 1
            if depth == 0:
                return j
    return -1


def split_args(tokens, open_i, close_i):
    """Split a parenthesised argument list into per-argument token slices."""
    args, depth, start = [], 0, open_i + 1
    for j in range(open_i + 1, close_i):
        t = tokens[j]
        if t.is_op("(", "[", "{"):
            depth += 1
        elif t.is_op(")", "]", "}"):
            depth -= 1
        elif t.is_op(",") and depth == 0:
            args.append(tokens[start:j])
            start = j + 1
    tail = tokens[start:close_i]
    if tail:
        args.append(tail)
    return args


def qualified_name(tokens, end_i):
    """Read a possibly-qualified callee name backwards from the '(' index.

    Turns  std::system  or  obj.method  or  ptr->run  into a single string
    so a rule can match on the last component.
    """
    parts, j = [], end_i - 1
    while j >= 0:
        t = tokens[j]
        if t.kind == IDENT:
            parts.append(t.value)
            j -= 1
            if j >= 0 and tokens[j].is_op("::", ".", "->"):
                parts.append(tokens[j].value)
                j -= 1
                continue
            break
        break
    return "".join(reversed(parts))


# ------------------------------------------------------------------ parser


def _structural_diagnostics(tokens):
    """Return lightweight syntax diagnostics for delimiter mismatches.

    This is intentionally not a compiler parser. It catches the most important
    failure mode for a linter: returning a reassuring zero-finding result when
    the source structure is visibly incomplete.
    """
    pairs = {")": "(", "]": "[", "}": "{"
    }
    opening = set(pairs.values())
    stack = []
    errors = []
    for token in tokens:
        if token.kind in (STRING, CHAR, PREPROC):
            continue
        if token.is_op("(", "[", "{"):
            stack.append((token.value, token.line, token.col))
        elif token.value in pairs:
            if not stack:
                errors.append((token.line, token.col, f"unexpected closing '{token.value}'"))
            elif stack[-1][0] != pairs[token.value]:
                want = stack[-1][0]
                errors.append((token.line, token.col,
                               f"mismatched closing '{token.value}', expected '{want}'"))
                stack.pop()
            else:
                stack.pop()
    for opener, line, col in stack:
        errors.append((line, col, f"unclosed '{opener}'"))
    return errors

def parse(source: str, filename: str = "<cpp>") -> Node:
    """Build a structural tree for one C++ translation unit."""
    tokens = tokenize(source)
    root = Node(TRANSLATION_UNIT, 1, 0, filename)
    root.extra["tokens"] = tokens
    root.extra["source"] = source
    root.extra["diagnostics"] = _structural_diagnostics(tokens)

    # Preprocessor directives are top level regardless of position.
    for t in tokens:
        if t.kind == PREPROC:
            head = t.value.split()[0] if t.value.split() else "#"
            root.add(Node(PREPROC_NODE, t.line, t.col, head,
                          tokens=[t], extra={"text": t.value}))

    _parse_range(tokens, 0, len(tokens) - 1, root)
    return root


def _parse_range(tokens, start, end, parent):
    """Walk a token range, attaching structural nodes to `parent`."""
    i = start
    while i < end:
        t = tokens[i]

        if t.kind in (PREPROC, EOF):
            i += 1
            continue

        # ---- using namespace X; -------------------------------------
        if t.is_kw("using"):
            j = i
            words = []
            while j < end and not tokens[j].is_op(";"):
                if tokens[j].kind == IDENT:
                    words.append(tokens[j].value)
                j += 1
            parent.add(Node(USING_DECL, t.line, t.col, " ".join(words),
                            tokens=tokens[i:j + 1]))
            i = j + 1
            continue

        # ---- control flow --------------------------------------------
        if t.kind == IDENT and t.value in CONTROL_KEYWORDS:
            node = parent.add(Node(CONTROL, t.line, t.col, t.value))
            if i + 1 < end and tokens[i + 1].is_op("("):
                close = _match_paren(tokens, i + 1)
                if close != -1:
                    _parse_expression(tokens, i + 2, close, node)
                    i = close + 1
                    continue
            i += 1
            continue

        # ---- delete / new at statement level -------------------------
        if t.is_kw("delete"):
            parent.add(Node(DELETE_EXPR, t.line, t.col, "delete"))
            i += 1
            continue
        if t.is_kw("new"):
            nm = tokens[i + 1].value if i + 1 < end and tokens[i + 1].kind == IDENT else ""
            parent.add(Node(NEW_EXPR, t.line, t.col, nm))
            i += 1
            continue

        # ---- identifier followed by '(' ------------------------------
        if t.kind == IDENT and t.value not in NON_CALL_KEYWORDS:
            # find the '(' that may follow a qualified name
            j = i
            while (j + 2 < end and tokens[j + 1].is_op("::", ".", "->")
                   and tokens[j + 2].kind == IDENT):
                j += 2
            if j + 1 < end and tokens[j + 1].is_op("("):
                open_i = j + 1
                close_i = _match_paren(tokens, open_i)
                if close_i == -1:
                    i += 1
                    continue

                after = tokens[close_i + 1] if close_i + 1 <= end else None
                is_def = after is not None and after.is_op("{")

                # a function definition looks like:  <type words> name(...) {
                prev = tokens[i - 1] if i > 0 else None
                looks_declared = (
                    prev is not None
                    and (prev.is_kw(*TYPE_WORDS) or prev.is_op("*", "&", ">")
                         or (prev.kind == IDENT and prev.value not in NON_CALL_KEYWORDS))
                )

                if is_def and looks_declared:
                    name = qualified_name(tokens, open_i)
                    body_open = close_i + 1
                    body_close = _match_brace(tokens, body_open)
                    if body_close == -1:
                        body_close = end
                    params = split_args(tokens, open_i, close_i)
                    fn = parent.add(Node(
                        FUNCTION_DEF, t.line, t.col, name,
                        tokens=tokens[i:body_close + 1],
                        extra={"params": params,
                               "body_start": tokens[body_open].line,
                               "body_end": tokens[body_close].line,
                               "end_line": tokens[body_close].line},
                    ))
                    _parse_range(tokens, body_open + 1, body_close, fn)
                    i = body_close + 1
                    continue

                # otherwise: a call expression
                _emit_call(tokens, i, open_i, close_i, parent)
                _parse_expression(tokens, open_i + 1, close_i, parent)
                i = close_i + 1
                continue

        # ---- declaration:  T name;   or   T name = expr;  ------------
        if t.kind == IDENT and t.value in TYPE_WORDS:
            j, depth, stop = i, 0, None
            while j < end:
                tk = tokens[j]
                if tk.is_op("(", "["):
                    depth += 1
                elif tk.is_op(")", "]"):
                    depth -= 1
                elif depth == 0 and tk.is_op(";"):
                    stop = ";"
                    break
                elif depth == 0 and tk.is_op("{"):
                    stop = "{"
                    break
                j += 1
            # A '{' before any ';' means this was a function or class
            # definition, not a variable - leave it for the branch above.
            if stop == "{":
                i += 1
                continue
            if stop == ";":
                _emit_declaration(tokens, i, j, parent)
                i = j + 1          # jump past the whole statement, no re-scan
                continue
            i += 1
            continue

        i += 1


def _parse_expression(tokens, start, end, parent):
    """Find calls / new / delete nested inside an expression range."""
    i = start
    while i < end:
        t = tokens[i]
        if t.is_kw("new"):
            nm = tokens[i + 1].value if i + 1 < end and tokens[i + 1].kind == IDENT else ""
            parent.add(Node(NEW_EXPR, t.line, t.col, nm))
            i += 1
            continue
        if t.is_kw("delete"):
            parent.add(Node(DELETE_EXPR, t.line, t.col, "delete"))
            i += 1
            continue
        if t.kind == IDENT and t.value not in NON_CALL_KEYWORDS:
            j = i
            while (j + 2 < end and tokens[j + 1].is_op("::", ".", "->")
                   and tokens[j + 2].kind == IDENT):
                j += 2
            if j + 1 < end and tokens[j + 1].is_op("("):
                open_i = j + 1
                close_i = _match_paren(tokens, open_i)
                if close_i != -1 and close_i <= end:
                    _emit_call(tokens, i, open_i, close_i, parent)
                    _parse_expression(tokens, open_i + 1, close_i, parent)
                    i = close_i + 1
                    continue
        i += 1


def _emit_call(tokens, name_i, open_i, close_i, parent):
    name = qualified_name(tokens, open_i)
    args = split_args(tokens, open_i, close_i)
    t = tokens[name_i]
    parent.add(Node(
        CALL_EXPR, t.line, t.col, name,
        tokens=tokens[name_i:close_i + 1],
        extra={"args": args, "bare": name.split("::")[-1].split(".")[-1].split("->")[-1]},
    ))


def _emit_declaration(tokens, start, end, parent):
    """Record  `const char* password = "hunter2";`  style declarations."""
    name, init = "", []
    eq = -1
    for j in range(start, end):
        if tokens[j].is_op("="):
            eq = j
            break

    if eq != -1:
        k = eq - 1
        init = tokens[eq + 1:end]
    else:
        # no initialiser - the declared name is the last identifier that is
        # not a type word, e.g.  char buf[64];  ->  buf
        k = end - 1
        while k >= start and (tokens[k].kind != IDENT or tokens[k].value in TYPE_WORDS):
            k -= 1

    while k >= start and (tokens[k].kind != IDENT or tokens[k].value in TYPE_WORDS):
        k -= 1
    if k >= start:
        name = tokens[k].value
    if not name:
        return

    node = Node(DECLARATION, tokens[start].line, tokens[start].col, name,
                tokens=tokens[start:end], extra={"init": init})
    parent.add(node)

    # a  new  inside the initialiser still needs to be visible to rules
    for j in range(start, end):
        if tokens[j].is_kw("new"):
            nm = tokens[j + 1].value if j + 1 < end and tokens[j + 1].kind == IDENT else ""
            node.add(Node(NEW_EXPR, tokens[j].line, tokens[j].col, nm))
        elif tokens[j].kind == IDENT and j + 1 < end and tokens[j + 1].is_op("("):
            close = _match_paren(tokens, j + 1)
            if close != -1 and close < end:
                _emit_call(tokens, j, j + 1, close, node)
