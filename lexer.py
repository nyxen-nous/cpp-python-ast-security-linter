"""
A C++ tokenizer.

This is the layer that makes C++ analysis structural rather than textual.
A regular expression searching for `gets` matches the word inside a comment,
inside a string literal, and inside the identifier `widgets`. A tokenizer
cannot make any of those mistakes, because by the time a rule sees a token
the lexer has already decided whether those characters were code.

Handles: line and block comments, string literals (including escapes and raw
strings), character literals, preprocessor directives, numbers, identifiers,
operators and punctuation - each carrying its line and column.
"""

from dataclasses import dataclass

# token kinds
IDENT = "identifier"
NUMBER = "number"
STRING = "string_literal"
CHAR = "char_literal"
COMMENT = "comment"
PREPROC = "preproc"
PUNCT = "punct"
EOF = "eof"

KEYWORDS = {
    "alignas", "alignof", "auto", "bool", "break", "case", "catch", "char",
    "class", "const", "constexpr", "continue", "default", "delete", "do",
    "double", "else", "enum", "explicit", "export", "extern", "false",
    "float", "for", "friend", "goto", "if", "inline", "int", "long",
    "mutable", "namespace", "new", "noexcept", "nullptr", "operator",
    "private", "protected", "public", "register", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "template", "this",
    "throw", "true", "try", "typedef", "typename", "union", "unsigned",
    "using", "virtual", "void", "volatile", "while",
}

# Longest first so that >>= is matched before >> and >.
OPERATORS = [
    "<<=", ">>=", "...", "->*", "<=>",
    "::", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ".*",
    "{", "}", "(", ")", "[", "]", ";", ",", ".", "?", ":",
    "+", "-", "*", "/", "%", "&", "|", "^", "!", "~", "=", "<", ">",
]


@dataclass
class Token:
    kind: str
    value: str
    line: int
    col: int

    def is_kw(self, *names):
        return self.kind == IDENT and self.value in names

    def is_op(self, *ops):
        return self.kind == PUNCT and self.value in ops

    def __repr__(self):
        return f"{self.kind}({self.value!r})@{self.line}:{self.col}"


def tokenize(source: str, keep_comments: bool = False):
    """Turn C++ source into a flat token list."""
    tokens = []
    i, line, col = 0, 1, 0
    n = len(source)

    def add(kind, value, ln, cl):
        tokens.append(Token(kind, value, ln, cl))

    while i < n:
        ch = source[i]

        # ---- newline -------------------------------------------------
        if ch == "\n":
            i += 1
            line += 1
            col = 0
            continue

        # ---- whitespace ----------------------------------------------
        if ch in " \t\r\v\f":
            i += 1
            col += 1
            continue

        start_line, start_col = line, col

        # ---- line comment --------------------------------------------
        if source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j == -1 else j
            if keep_comments:
                add(COMMENT, source[i:j], start_line, start_col)
            col += j - i
            i = j
            continue

        # ---- block comment -------------------------------------------
        if source.startswith("/*", i):
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            chunk = source[i:j]
            if keep_comments:
                add(COMMENT, chunk, start_line, start_col)
            nl = chunk.count("\n")
            if nl:
                line += nl
                col = len(chunk) - chunk.rfind("\n") - 1
            else:
                col += len(chunk)
            i = j
            continue

        # ---- preprocessor directive ----------------------------------
        if ch == "#" and (not tokens or tokens[-1].line < line or col == start_col):
            j = i
            while j < n:
                nxt = source.find("\n", j)
                if nxt == -1:
                    j = n
                    break
                # a trailing backslash continues the directive
                if source[nxt - 1: nxt] == "\\":
                    j = nxt + 1
                    continue
                j = nxt
                break
            chunk = source[i:j]
            add(PREPROC, chunk, start_line, start_col)
            line += chunk.count("\n")
            col = 0
            i = j
            continue

        # ---- raw string  R"delim( ... )delim" ------------------------
        if ch == "R" and source.startswith('R"', i):
            k = source.find("(", i + 2)
            if k != -1:
                delim = source[i + 2:k]
                close = ')' + delim + '"'
                j = source.find(close, k)
                j = n if j == -1 else j + len(close)
                chunk = source[i:j]
                add(STRING, chunk, start_line, start_col)
                nl = chunk.count("\n")
                if nl:
                    line += nl
                    col = len(chunk) - chunk.rfind("\n") - 1
                else:
                    col += len(chunk)
                i = j
                continue

        # ---- string / char literal -----------------------------------
        if ch in "\"'":
            quote = ch
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == quote:
                    j += 1
                    break
                if source[j] == "\n":
                    break
                j += 1
            chunk = source[i:j]
            add(STRING if quote == '"' else CHAR, chunk, start_line, start_col)
            col += len(chunk)
            i = j
            continue

        # ---- number ---------------------------------------------------
        if ch.isdigit() or (ch == "." and i + 1 < n and source[i + 1].isdigit()):
            j = i
            while j < n and (source[j].isalnum() or source[j] in "._'"):
                j += 1
            add(NUMBER, source[i:j], start_line, start_col)
            col += j - i
            i = j
            continue

        # ---- identifier / keyword -------------------------------------
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (source[j].isalnum() or source[j] == "_"):
                j += 1
            add(IDENT, source[i:j], start_line, start_col)
            col += j - i
            i = j
            continue

        # ---- operator / punctuation -----------------------------------
        for op in OPERATORS:
            if source.startswith(op, i):
                add(PUNCT, op, start_line, start_col)
                i += len(op)
                col += len(op)
                break
        else:
            i += 1
            col += 1

    add(EOF, "", line, col)
    return tokens


def string_body(tok: Token) -> str:
    """The text inside a string literal, without its quotes or prefix."""
    v = tok.value
    if v.startswith('R"'):
        k = v.find("(")
        return v[k + 1: v.rfind(")")] if k != -1 else v
    a, b = v.find('"'), v.rfind('"')
    if a != -1 and b > a:
        return v[a + 1:b]
    a, b = v.find("'"), v.rfind("'")
    if a != -1 and b > a:
        return v[a + 1:b]
    return v
